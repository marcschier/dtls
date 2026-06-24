using System;
using System.Collections.Generic;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Threading;
using System.Threading.Tasks;
using Dtls.Crypto;
using Dtls.Internal;
using Dtls.Transport;

namespace Dtls.Protocol.V13.Handshake;

/// <summary>
/// The managed DTLS 1.3 server handshake driver (RFC 9147 / RFC 8446). It parses the
/// buffered ClientHello, selects a cipher suite and group, and then runs either the
/// external-PSK + ECDHE (psk_dhe_ke) flow or the certificate-authenticated (EC)DHE flow,
/// depending on the configured credentials and the client's offer. It replies with a
/// ServerHello and a protected epoch-2 flight, verifies the client's Finished, and returns
/// an established connection.
/// </summary>
/// <remarks>
/// On the certificate path the server can request client authentication
/// (<see cref="DtlsServerOptions.RequireClientCertificate"/>) and perform a stateless
/// HelloRetryRequest cookie exchange (<see cref="DtlsServerOptions.EnableStatelessRetry"/>).
/// Handshake flights are driven through a <see cref="Dtls13FlightTransceiver"/> that retransmits
/// on loss and de-duplicates retransmitted peer flights (RFC 9147 section 5.8); the client's final
/// flight is acknowledged (section 7). Deferred (not implemented here): handshake message
/// fragmentation across datagrams (single-datagram flights are assumed) and 0-RTT. The external-PSK
/// path does not emit a HelloRetryRequest.
/// </remarks>
internal static class Dtls13ServerHandshake
{
    public static async Task<DtlsConnection> RunAsync(
        IDatagramTransport transport,
        DtlsServerOptions options,
        ReadOnlyMemory<byte> initialDatagram,
        CancellationToken cancellationToken)
    {
        if (options.PskCallback is null && options.ServerCertificate is null)
        {
            throw new DtlsException(
                "The managed DTLS 1.3 server requires a PskCallback or a ServerCertificate.");
        }

        if (!Dtls13HandshakeRecords.TryReadPlaintextHandshake(
                initialDatagram.Span, out HandshakeType chType, out byte[] clientHelloBody)
            || chType != HandshakeType.ClientHello
            || !ClientHello.TryParse(clientHelloBody, out ClientHello clientHello))
        {
            throw new DtlsException("The initial datagram was not a valid ClientHello.");
        }

        Dtls13CipherSuite suite = SelectCipherSuite(
            clientHello, CipherSuitePolicy.Resolve(options.CipherSuites));
        HashAlgorithmName hash = suite.HashAlgorithm;
        NamedGroup group = SelectGroup(clientHello, out byte[] clientKeyShare);

        (byte[] serverConnectionId, byte[] clientConnectionId) =
            NegotiateConnectionId(options, clientHello);

        Dtls13FlightTransceiver transceiver = new(
            transport, options.HandshakeRetransmissionTimeout, options.MaxHandshakeRetransmissions);
        transceiver.Seed(initialDatagram.Span);

        if (UseCertificate(options, clientHello))
        {
            byte[]? transcriptPrefix = null;
            if (options.EnableStatelessRetry)
            {
                HelloRetryExchange retry = await RunStatelessHelloRetryAsync(
                        transceiver,
                        clientHello,
                        clientHelloBody,
                        suite,
                        group,
                        serverConnectionId,
                        cancellationToken)
                    .ConfigureAwait(false);
                clientHello = retry.ClientHello;
                clientHelloBody = retry.ClientHelloBody;
                clientKeyShare = retry.ClientKeyShare;
                group = retry.Group;
                transcriptPrefix = retry.TranscriptPrefix;
            }

            CertificateType certificateType = SelectServerCertificateType(
                options, clientHello, out bool emitCertificateTypeExtension);

            return await RunCertificateAsync(
                    transceiver,
                    options.ServerCertificate!,
                    clientHello,
                    clientHelloBody,
                    suite,
                    hash,
                    group,
                    clientKeyShare,
                    certificateType,
                    emitCertificateTypeExtension,
                    serverConnectionId,
                    clientConnectionId,
                    options.RequireClientCertificate,
                    options.ClientCertificateValidation,
                    transcriptPrefix,
                    cancellationToken)
                .ConfigureAwait(false);
        }

        return await RunPskAsync(
                transceiver,
                options.PskCallback!,
                clientHello,
                clientHelloBody,
                suite,
                hash,
                group,
                clientKeyShare,
                serverConnectionId,
                clientConnectionId,
                cancellationToken)
            .ConfigureAwait(false);
    }

    private sealed class HelloRetryExchange
    {
        public HelloRetryExchange(
            ClientHello clientHello,
            byte[] clientHelloBody,
            byte[] clientKeyShare,
            NamedGroup group,
            byte[] transcriptPrefix)
        {
            ClientHello = clientHello;
            ClientHelloBody = clientHelloBody;
            ClientKeyShare = clientKeyShare;
            Group = group;
            TranscriptPrefix = transcriptPrefix;
        }

        public ClientHello ClientHello { get; }

        public byte[] ClientHelloBody { get; }

        public byte[] ClientKeyShare { get; }

        public NamedGroup Group { get; }

        public byte[] TranscriptPrefix { get; }
    }

    /// <summary>
    /// Runs a stateless HelloRetryRequest round (RFC 9147 section 5.1): the server emits an
    /// HRR carrying an authenticated cookie (and, when the client offered an additional group
    /// without a key_share, a request for that group), then receives and validates the second
    /// ClientHello. Returns the second ClientHello together with the synthetic
    /// <c>message_hash</c> + HelloRetryRequest transcript prefix (RFC 8446 section 4.4.1).
    /// </summary>
    private static async Task<HelloRetryExchange> RunStatelessHelloRetryAsync(
        Dtls13FlightTransceiver transceiver,
        ClientHello clientHello1,
        byte[] clientHello1Body,
        Dtls13CipherSuite suite,
        NamedGroup group,
        byte[] serverConnectionId,
        CancellationToken cancellationToken)
    {
        HashAlgorithmName hash = suite.HashAlgorithm;
        byte[] clientHello1Reconstructed = HandshakeMessage.ToTranscriptBytes(
            HandshakeType.ClientHello, clientHello1Body);

        byte[] clientHello1Hash;
        using (IncrementalHash digest = IncrementalHash.CreateHash(hash))
        {
            digest.AppendData(clientHello1Reconstructed);
            clientHello1Hash = digest.GetHashAndReset();
        }

        // Prefer changing the client to an offered-but-unshared group (so the HelloRetryRequest
        // also corrects the key_share); otherwise fall back to a cookie-only retry that keeps
        // the originally selected group.
        bool changeGroup = TrySelectUnsharedGroup(clientHello1, out NamedGroup retryGroup);
        NamedGroup expectedGroup = changeGroup ? retryGroup : group;

        byte[] macKey = new byte[32];
        RandomNumberGenerator.Fill(macKey);
        try
        {
            byte[] cookie = HelloRetryCookie.Build(macKey, expectedGroup, clientHello1Hash);
            byte[] helloRetryBody = BuildHelloRetryRequestBody(
                suite, changeGroup ? expectedGroup : (NamedGroup?)null, cookie, serverConnectionId);

            byte[] helloRetryMessage = HandshakeMessage.Serialize(
                HandshakeType.ServerHello, 0, helloRetryBody);
            byte[] helloRetryRecord = Dtls13PlaintextRecord.Encode(
                Dtls13PlaintextRecord.HandshakeContentType, 0, 0, helloRetryMessage);
            await transceiver.SendAsync(helloRetryRecord, cancellationToken).ConfigureAwait(false);

            byte[] clientHello2Datagram = await transceiver.ReceiveFlightAsync(cancellationToken)
                .ConfigureAwait(false);
            if (!Dtls13HandshakeRecords.TryReadPlaintextHandshake(
                    clientHello2Datagram, out HandshakeType ch2Type, out byte[] clientHello2Body)
                || ch2Type != HandshakeType.ClientHello
                || !ClientHello.TryParse(clientHello2Body, out ClientHello clientHello2))
            {
                throw new DtlsAlertException(
                    DtlsAlert.DecodeError,
                    true,
                    "Expected a second ClientHello after the HelloRetryRequest.");
            }

            if (!ExtensionList.TryFind(
                    clientHello2.Extensions, ExtensionType.Cookie, out HandshakeExtension cookieExt)
                || !CookieExtension.TryParse(cookieExt.Data, out byte[] echoed)
                || !HelloRetryCookie.TryOpen(
                    macKey, echoed, out NamedGroup cookieGroup, out byte[] cookieHash)
                || cookieGroup != expectedGroup
                || !CryptographicOperations.FixedTimeEquals(cookieHash, clientHello1Hash))
            {
                throw new DtlsAlertException(
                    DtlsAlert.HandshakeFailure,
                    true,
                    "The HelloRetryRequest cookie was missing or invalid.");
            }

            NamedGroup group2 = SelectGroup(clientHello2, out byte[] clientKeyShare2);
            if (group2 != expectedGroup)
            {
                throw new DtlsAlertException(
                    DtlsAlert.IllegalParameter,
                    true,
                    "The second ClientHello did not use the HelloRetryRequest group.");
            }

            byte[] messageHash = TranscriptHash.SynthesizeMessageHash(
                hash, clientHello1Reconstructed);
            byte[] helloRetryTranscript = HandshakeMessage.ToTranscriptBytes(
                HandshakeType.ServerHello, helloRetryBody);
            byte[] transcriptPrefix = new byte[messageHash.Length + helloRetryTranscript.Length];
            messageHash.CopyTo(transcriptPrefix, 0);
            helloRetryTranscript.CopyTo(transcriptPrefix, messageHash.Length);

            return new HelloRetryExchange(
                clientHello2, clientHello2Body, clientKeyShare2, expectedGroup, transcriptPrefix);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(macKey);
        }
    }

    /// <summary>
    /// Finds the first mutually supported group the client offered in supported_groups but did
    /// not provide a key_share for. Used to drive a HelloRetryRequest that also corrects the
    /// client's key_share (RFC 8446 section 4.1.4).
    /// </summary>
    private static bool TrySelectUnsharedGroup(ClientHello clientHello, out NamedGroup group)
    {
        group = default;

        if (!ExtensionList.TryFind(
                clientHello.Extensions,
                ExtensionType.SupportedGroups,
                out HandshakeExtension groupsExt)
            || !SupportedGroupsExtension.TryParse(groupsExt.Data, out List<NamedGroup> groups))
        {
            return false;
        }

        HashSet<NamedGroup> shared = new();
        if (ExtensionList.TryFind(
                clientHello.Extensions, ExtensionType.KeyShare, out HandshakeExtension keyShareExt)
            && KeyShareExtension.TryParseClientHello(
                keyShareExt.Data, out List<KeyShareEntry> shares))
        {
            foreach (KeyShareEntry entry in shares)
            {
                shared.Add(entry.Group);
            }
        }

        foreach (NamedGroup candidate in groups)
        {
            if (EcdheKeyExchange.IsSupported(candidate) && !shared.Contains(candidate))
            {
                group = candidate;
                return true;
            }
        }

        return false;
    }

    private static byte[] BuildHelloRetryRequestBody(
        Dtls13CipherSuite suite,
        NamedGroup? selectedGroup,
        byte[] cookie,
        byte[] serverConnectionId)
    {
        List<HandshakeExtension> extensions = new()
        {
            new HandshakeExtension(
                ExtensionType.SupportedVersions,
                SupportedVersionsExtension.EncodeServerHello(DtlsWireVersion.Dtls13)),
        };

        if (selectedGroup is { } group)
        {
            extensions.Add(new HandshakeExtension(
                ExtensionType.KeyShare, KeyShareExtension.EncodeHelloRetryRequest(group)));
        }

        extensions.Add(new HandshakeExtension(
            ExtensionType.Cookie, CookieExtension.Encode(cookie)));

        AddConnectionIdExtension(extensions, serverConnectionId);

        ServerHello helloRetryRequest = new()
        {
            Random = ServerHello.HelloRetryRequestRandom.ToArray(),
            CipherSuite = suite.Id,
            Extensions = extensions,
        };
        return helloRetryRequest.Encode();
    }

    private static (byte[] ServerCid, byte[] ClientCid) NegotiateConnectionId(
        DtlsServerOptions options, ClientHello clientHello)
    {
        if (!options.UseConnectionId
            || clientHello.Extensions is null
            || !ExtensionList.TryFind(
                clientHello.Extensions,
                ExtensionType.ConnectionId,
                out HandshakeExtension extension)
            || !ConnectionIdExtension.TryParse(extension.Data, out byte[] clientCid))
        {
            return (Array.Empty<byte>(), Array.Empty<byte>());
        }

        byte[] serverCid = new byte[8];
        RandomNumberGenerator.Fill(serverCid);
        return (serverCid, clientCid);
    }

    private static Dtls13Connection CreateServerConnection(
        IDatagramTransport transport,
        Dtls13CipherSuite suite,
        byte[] serverApplicationSecret,
        byte[] clientApplicationSecret,
        byte[] serverConnectionId,
        byte[] clientConnectionId)
    {
        if (serverConnectionId.Length > 0)
        {
            return Dtls13Connection.Create(
                transport,
                suite,
                serverApplicationSecret,
                clientApplicationSecret,
                sendConnectionId: clientConnectionId,
                receiveConnectionIdLength: serverConnectionId.Length);
        }

        return Dtls13Connection.Create(
            transport, suite, serverApplicationSecret, clientApplicationSecret);
    }

    private static async Task<DtlsConnection> RunPskAsync(
        Dtls13FlightTransceiver transceiver,
        DtlsPskServerCallback pskCallback,
        ClientHello clientHello,
        byte[] clientHelloBody,
        Dtls13CipherSuite suite,
        HashAlgorithmName hash,
        NamedGroup group,
        byte[] clientKeyShare,
        byte[] serverConnectionId,
        byte[] clientConnectionId,
        CancellationToken cancellationToken)
    {
        if (!HasPskDheKeMode(clientHello))
        {
            throw new DtlsAlertException(
                DtlsAlert.MissingExtension, true, "The client did not offer psk_dhe_ke.");
        }

        List<byte[]> secrets = new();
        using EcdheKeyExchange ecdhe = EcdheKeyExchange.Create(group);
        Dtls13RecordProtector? sendHandshake = null;
        Dtls13RecordProtector? recvHandshake = null;
        try
        {
            ushort selectedIdentity = ResolveAndVerifyPsk(
                clientHello, clientHelloBody, hash, pskCallback, out byte[] pskKey);
            secrets.Add(pskKey);

            TranscriptHash transcript = new(hash);
            transcript.AppendMessage(HandshakeType.ClientHello, clientHelloBody);

            byte[] early = Dtls13KeySchedule.EarlySecret(hash, pskKey);
            secrets.Add(early);

            byte[] serverKeyShare = ecdhe.ExportKeyShare();
            byte[] ecdheSecret = ecdhe.DeriveSharedSecret(clientKeyShare);
            secrets.Add(ecdheSecret);

            byte[] serverHelloBody = BuildServerHelloBody(
                suite, group, serverKeyShare, selectedIdentity, serverConnectionId);
            transcript.AppendMessage(HandshakeType.ServerHello, serverHelloBody);

            byte[] serverHelloMessage = HandshakeMessage.Serialize(
                HandshakeType.ServerHello, 0, serverHelloBody);
            byte[] serverHelloRecord = Dtls13PlaintextRecord.Encode(
                Dtls13PlaintextRecord.HandshakeContentType, 0, 0, serverHelloMessage);
            await transceiver.SendAsync(serverHelloRecord, cancellationToken)
                .ConfigureAwait(false);

            byte[] handshakeSecret = Dtls13KeySchedule.DeriveHandshakeSecret(
                hash, early, ecdheSecret);
            secrets.Add(handshakeSecret);

            byte[] transcriptChSh = transcript.CurrentHash();
            byte[] clientHsSecret = Dtls13KeySchedule.DeriveClientHandshakeTrafficSecret(
                hash, handshakeSecret, transcriptChSh);
            byte[] serverHsSecret = Dtls13KeySchedule.DeriveServerHandshakeTrafficSecret(
                hash, handshakeSecret, transcriptChSh);
            secrets.Add(clientHsSecret);
            secrets.Add(serverHsSecret);

            sendHandshake = Dtls13HandshakeRecords.CreateProtector(suite, serverHsSecret);
            recvHandshake = Dtls13HandshakeRecords.CreateProtector(suite, clientHsSecret);

            byte[] encryptedExtensionsBody = EncryptedExtensions.Encode(
                Array.Empty<HandshakeExtension>());
            transcript.AppendMessage(HandshakeType.EncryptedExtensions, encryptedExtensionsBody);

            byte[] transcriptChEe = transcript.CurrentHash();
            byte[] serverFinished = Dtls13KeySchedule.ComputeVerifyData(
                hash, serverHsSecret, transcriptChEe);
            transcript.AppendMessage(HandshakeType.Finished, serverFinished);

            byte[] eeMessage = HandshakeMessage.Serialize(
                HandshakeType.EncryptedExtensions, 1, encryptedExtensionsBody);
            byte[] finishedMessage = HandshakeMessage.Serialize(
                HandshakeType.Finished, 2, serverFinished);
            byte[] eeRecord = Dtls13HandshakeRecords.SealHandshakeRecord(
                sendHandshake, 0, eeMessage);
            byte[] finishedRecord = Dtls13HandshakeRecords.SealHandshakeRecord(
                sendHandshake, 1, finishedMessage);

            byte[] flight = new byte[eeRecord.Length + finishedRecord.Length];
            eeRecord.CopyTo(flight, 0);
            finishedRecord.CopyTo(flight, eeRecord.Length);
            await transceiver.SendAsync(flight, cancellationToken).ConfigureAwait(false);

            byte[] transcriptChSf = transcript.CurrentHash();
            byte[] master = Dtls13KeySchedule.DeriveMasterSecret(hash, handshakeSecret);
            byte[] clientAp = Dtls13KeySchedule.DeriveClientApplicationTrafficSecret(
                hash, master, transcriptChSf);
            byte[] serverAp = Dtls13KeySchedule.DeriveServerApplicationTrafficSecret(
                hash, master, transcriptChSf);
            secrets.Add(master);
            secrets.Add(clientAp);
            secrets.Add(serverAp);

            await ReceiveAndVerifyClientFinishedAsync(
                    transceiver,
                    recvHandshake,
                    hash,
                    clientHsSecret,
                    transcriptChSf,
                    cancellationToken)
                .ConfigureAwait(false);

            await SendHandshakeAckAsync(
                    transceiver, sendHandshake, recvHandshake, 2, cancellationToken)
                .ConfigureAwait(false);

            return CreateServerConnection(
                transceiver.Transport,
                suite,
                serverAp,
                clientAp,
                serverConnectionId,
                clientConnectionId);
        }
        finally
        {
            sendHandshake?.Dispose();
            recvHandshake?.Dispose();
            foreach (byte[] secret in secrets)
            {
                CryptographicOperations.ZeroMemory(secret);
            }
        }
    }

    private static async Task<DtlsConnection> RunCertificateAsync(
        Dtls13FlightTransceiver transceiver,
        X509Certificate2 certificate,
        ClientHello clientHello,
        byte[] clientHelloBody,
        Dtls13CipherSuite suite,
        HashAlgorithmName hash,
        NamedGroup group,
        byte[] clientKeyShare,
        CertificateType certificateType,
        bool emitCertificateTypeExtension,
        byte[] serverConnectionId,
        byte[] clientConnectionId,
        bool requireClientCertificate,
        DtlsRemoteCertificateValidation? clientCertificateValidation,
        byte[]? transcriptPrefix,
        CancellationToken cancellationToken)
    {
        SignatureScheme scheme = SelectSignatureScheme(clientHello, certificate);

        List<byte[]> secrets = new();
        using EcdheKeyExchange ecdhe = EcdheKeyExchange.Create(group);
        Dtls13RecordProtector? sendHandshake = null;
        Dtls13RecordProtector? recvHandshake = null;
        try
        {
            TranscriptHash transcript = new(hash);
            if (transcriptPrefix is not null)
            {
                transcript.AppendRaw(transcriptPrefix);
            }

            transcript.AppendMessage(HandshakeType.ClientHello, clientHelloBody);

            byte[] early = Dtls13KeySchedule.EarlySecret(hash, ReadOnlySpan<byte>.Empty);
            secrets.Add(early);

            byte[] serverKeyShare = ecdhe.ExportKeyShare();
            byte[] ecdheSecret = ecdhe.DeriveSharedSecret(clientKeyShare);
            secrets.Add(ecdheSecret);

            byte[] serverHelloBody = BuildCertificateServerHelloBody(
                suite, group, serverKeyShare, serverConnectionId);
            transcript.AppendMessage(HandshakeType.ServerHello, serverHelloBody);

            byte[] serverHelloMessage = HandshakeMessage.Serialize(
                HandshakeType.ServerHello, 0, serverHelloBody);
            byte[] serverHelloRecord = Dtls13PlaintextRecord.Encode(
                Dtls13PlaintextRecord.HandshakeContentType, 0, 0, serverHelloMessage);
            await transceiver.SendAsync(serverHelloRecord, cancellationToken)
                .ConfigureAwait(false);

            byte[] handshakeSecret = Dtls13KeySchedule.DeriveHandshakeSecret(
                hash, early, ecdheSecret);
            secrets.Add(handshakeSecret);

            byte[] transcriptChSh = transcript.CurrentHash();
            byte[] clientHsSecret = Dtls13KeySchedule.DeriveClientHandshakeTrafficSecret(
                hash, handshakeSecret, transcriptChSh);
            byte[] serverHsSecret = Dtls13KeySchedule.DeriveServerHandshakeTrafficSecret(
                hash, handshakeSecret, transcriptChSh);
            secrets.Add(clientHsSecret);
            secrets.Add(serverHsSecret);

            sendHandshake = Dtls13HandshakeRecords.CreateProtector(suite, serverHsSecret);
            recvHandshake = Dtls13HandshakeRecords.CreateProtector(suite, clientHsSecret);

            byte[] encryptedExtensionsBody = BuildCertificateEncryptedExtensions(
                certificateType, emitCertificateTypeExtension);
            transcript.AppendMessage(HandshakeType.EncryptedExtensions, encryptedExtensionsBody);

            byte[]? certificateRequestBody = null;
            if (requireClientCertificate)
            {
                certificateRequestBody = CertificateRequestMessage.Encode(ClientCertificateSchemes);
                transcript.AppendMessage(
                    HandshakeType.CertificateRequest, certificateRequestBody);
            }

            byte[] certificateData = certificateType == CertificateType.RawPublicKey
                ? RawPublicKey.ExportSubjectPublicKeyInfo(certificate)
                : certificate.RawData;
            byte[] certificateBody = CertificateMessage.Encode(new[] { certificateData });
            transcript.AppendMessage(HandshakeType.Certificate, certificateBody);

            byte[] transcriptThroughCert = transcript.CurrentHash();
            byte[] signature = CertificateVerifySigner.Sign(
                certificate, scheme, transcriptThroughCert);
            byte[] certificateVerifyBody = CertificateVerifyMessage.Encode(scheme, signature);
            transcript.AppendMessage(HandshakeType.CertificateVerify, certificateVerifyBody);

            byte[] transcriptThroughCv = transcript.CurrentHash();
            byte[] serverFinished = Dtls13KeySchedule.ComputeVerifyData(
                hash, serverHsSecret, transcriptThroughCv);
            transcript.AppendMessage(HandshakeType.Finished, serverFinished);

            byte[] flight = BuildCertificateServerFlight(
                sendHandshake,
                encryptedExtensionsBody,
                certificateRequestBody,
                certificateBody,
                certificateVerifyBody,
                serverFinished);
            await transceiver.SendAsync(flight, cancellationToken).ConfigureAwait(false);

            byte[] transcriptChSf = transcript.CurrentHash();
            byte[] master = Dtls13KeySchedule.DeriveMasterSecret(hash, handshakeSecret);
            byte[] clientAp = Dtls13KeySchedule.DeriveClientApplicationTrafficSecret(
                hash, master, transcriptChSf);
            byte[] serverAp = Dtls13KeySchedule.DeriveServerApplicationTrafficSecret(
                hash, master, transcriptChSf);
            secrets.Add(master);
            secrets.Add(clientAp);
            secrets.Add(serverAp);

            if (requireClientCertificate)
            {
                await ReceiveAndVerifyClientAuthAsync(
                        transceiver,
                        recvHandshake,
                        hash,
                        clientHsSecret,
                        transcript,
                        clientCertificateValidation,
                        cancellationToken)
                    .ConfigureAwait(false);
            }
            else
            {
                await ReceiveAndVerifyClientFinishedAsync(
                        transceiver,
                        recvHandshake,
                        hash,
                        clientHsSecret,
                        transcriptChSf,
                        cancellationToken)
                    .ConfigureAwait(false);
            }

            ulong ackSequence = requireClientCertificate ? 5UL : 4UL;
            await SendHandshakeAckAsync(
                    transceiver, sendHandshake, recvHandshake, ackSequence, cancellationToken)
                .ConfigureAwait(false);

            return CreateServerConnection(
                transceiver.Transport,
                suite,
                serverAp,
                clientAp,
                serverConnectionId,
                clientConnectionId);
        }
        finally
        {
            sendHandshake?.Dispose();
            recvHandshake?.Dispose();
            foreach (byte[] secret in secrets)
            {
                CryptographicOperations.ZeroMemory(secret);
            }
        }
    }

    private static byte[] BuildCertificateServerFlight(
        Dtls13RecordProtector protector,
        byte[] encryptedExtensionsBody,
        byte[]? certificateRequestBody,
        byte[] certificateBody,
        byte[] certificateVerifyBody,
        byte[] serverFinished)
    {
        List<byte[]> records = new();
        ushort messageSequence = 1;
        ulong recordSequence = 0;

        void Add(HandshakeType type, byte[] body)
        {
            byte[] message = HandshakeMessage.Serialize(type, messageSequence, body);
            records.Add(Dtls13HandshakeRecords.SealHandshakeRecord(
                protector, recordSequence, message));
            messageSequence++;
            recordSequence++;
        }

        Add(HandshakeType.EncryptedExtensions, encryptedExtensionsBody);
        if (certificateRequestBody is not null)
        {
            Add(HandshakeType.CertificateRequest, certificateRequestBody);
        }

        Add(HandshakeType.Certificate, certificateBody);
        Add(HandshakeType.CertificateVerify, certificateVerifyBody);
        Add(HandshakeType.Finished, serverFinished);

        int total = 0;
        foreach (byte[] record in records)
        {
            total += record.Length;
        }

        byte[] flight = new byte[total];
        int offset = 0;
        foreach (byte[] record in records)
        {
            record.CopyTo(flight, offset);
            offset += record.Length;
        }

        return flight;
    }

    private static readonly SignatureScheme[] ClientCertificateSchemes =
    {
        SignatureScheme.EcdsaSecp256r1Sha256,
        SignatureScheme.EcdsaSecp384r1Sha384,
        SignatureScheme.RsaPssRsaeSha256,
        SignatureScheme.RsaPssRsaeSha384,
    };

    private static async Task ReceiveAndVerifyClientAuthAsync(
        Dtls13FlightTransceiver transceiver,
        Dtls13RecordProtector recvHandshake,
        HashAlgorithmName hash,
        byte[] clientHsSecret,
        TranscriptHash transcript,
        DtlsRemoteCertificateValidation? clientCertificateValidation,
        CancellationToken cancellationToken)
    {
        byte[] datagram = await transceiver.ReceiveFlightAsync(cancellationToken)
            .ConfigureAwait(false);
        List<Dtls13HandshakeRecords.Message> flight =
            Dtls13HandshakeRecords.OpenHandshakeFlight(datagram, recvHandshake);

        if (flight.Count < 2 || flight[0].Type != HandshakeType.Certificate)
        {
            throw new DtlsException("Expected the client Certificate message.");
        }

        if (!CertificateMessage.TryParse(
                flight[0].Body, out _, out List<byte[]> certificateEntries))
        {
            throw new DtlsAlertException(
                DtlsAlert.DecodeError, true, "The client Certificate message was malformed.");
        }

        if (certificateEntries.Count == 0)
        {
            throw new DtlsAlertException(
                DtlsAlert.HandshakeFailure,
                true,
                "The server requires a client certificate, but none was provided.");
        }

        transcript.AppendMessage(HandshakeType.Certificate, flight[0].Body);
        byte[] transcriptThroughClientCert = transcript.CurrentHash();

        if (flight.Count < 3 || flight[1].Type != HandshakeType.CertificateVerify)
        {
            throw new DtlsException("Expected the client CertificateVerify message.");
        }

        if (!CertificateVerifyMessage.TryParse(
                flight[1].Body, out SignatureScheme scheme, out byte[] signature))
        {
            throw new DtlsAlertException(
                DtlsAlert.DecodeError,
                true,
                "The client CertificateVerify message was malformed.");
        }

        using (X509Certificate2 clientCertificate = LoadCertificate(certificateEntries[0]))
        {
            if (!CertificateVerifySigner.Verify(
                    clientCertificate,
                    scheme,
                    transcriptThroughClientCert,
                    signature,
                    clientContext: true))
            {
                throw new DtlsAlertException(
                    DtlsAlert.DecryptError,
                    true,
                    "The client CertificateVerify did not verify.");
            }

            if (clientCertificateValidation is { } validate
                && !validate(clientCertificate, null, true))
            {
                throw new DtlsAlertException(
                    DtlsAlert.BadCertificate,
                    true,
                    "The client certificate was rejected by the validation callback.");
            }
        }

        transcript.AppendMessage(HandshakeType.CertificateVerify, flight[1].Body);
        byte[] transcriptThroughClientCv = transcript.CurrentHash();

        if (flight.Count < 3 || flight[2].Type != HandshakeType.Finished)
        {
            throw new DtlsException("Expected the client Finished message.");
        }

        if (!Dtls13KeySchedule.VerifyFinished(
                hash, clientHsSecret, transcriptThroughClientCv, flight[2].Body))
        {
            throw new DtlsAlertException(
                DtlsAlert.DecryptError, true, "The client Finished did not verify.");
        }
    }

    private static X509Certificate2 LoadCertificate(byte[] der)
    {
#if NET9_0_OR_GREATER
        return X509CertificateLoader.LoadCertificate(der);
#else
        return new X509Certificate2(der);
#endif
    }

    private static async Task ReceiveAndVerifyClientFinishedAsync(
        Dtls13FlightTransceiver transceiver,
        Dtls13RecordProtector recvHandshake,
        HashAlgorithmName hash,
        byte[] clientHsSecret,
        byte[] transcriptChSf,
        CancellationToken cancellationToken)
    {
        byte[] finishedDatagram = await transceiver.ReceiveFlightAsync(cancellationToken)
            .ConfigureAwait(false);
        List<Dtls13HandshakeRecords.Message> clientFlight =
            Dtls13HandshakeRecords.OpenHandshakeFlight(finishedDatagram, recvHandshake);

        if (clientFlight.Count < 1 || clientFlight[0].Type != HandshakeType.Finished)
        {
            throw new DtlsException("Expected the client Finished message.");
        }

        if (!Dtls13KeySchedule.VerifyFinished(
                hash, clientHsSecret, transcriptChSf, clientFlight[0].Body))
        {
            throw new DtlsAlertException(
                DtlsAlert.DecryptError, true, "The client Finished did not verify.");
        }
    }

    private static async Task SendHandshakeAckAsync(
        Dtls13FlightTransceiver transceiver,
        Dtls13RecordProtector sendHandshake,
        Dtls13RecordProtector recvHandshake,
        ulong sequenceNumber,
        CancellationToken cancellationToken)
    {
        // Acknowledge the client's final flight (RFC 9147 section 7) so a lost client Finished is
        // retransmitted, then drain the client's ACK of our ACK. Draining returns as soon as the
        // client acknowledges (the common no-loss case incurs no extra wait) or when the client
        // goes quiet, so the handshake reliably completes before the connection is returned.
        byte[] ackRecord = Dtls13HandshakeRecords.SealAckRecord(
            sendHandshake, sequenceNumber, new[] { new RecordNumber(2, 0) });
        await transceiver.SendAsync(ackRecord, cancellationToken).ConfigureAwait(false);

        // The client retransmits its Finished (and is re-ACKed via duplicate detection) until it
        // sees this ACK; once it does it sends an ACK back. A small timeout budget bounds how long
        // we wait when that final ACK is itself lost, since the handshake is already complete.
        const int drainRetransmissions = 4;
        while (true)
        {
            byte[]? datagram = await transceiver
                .TryReceiveFlightAsync(drainRetransmissions, cancellationToken)
                .ConfigureAwait(false);
            if (datagram is null
                || Dtls13HandshakeRecords.ContainsAck(datagram, recvHandshake))
            {
                return;
            }
        }
    }

    private static bool UseCertificate(DtlsServerOptions options, ClientHello clientHello)
    {
        if (options.ServerCertificate is null)
        {
            return false;
        }

        if (options.PskCallback is null)
        {
            return true;
        }

        bool clientOfferedPsk = HasPskDheKeMode(clientHello)
            && ExtensionList.TryFind(clientHello.Extensions, ExtensionType.PreSharedKey, out _);
        return !clientOfferedPsk;
    }

    private static CertificateType SelectServerCertificateType(
        DtlsServerOptions options,
        ClientHello clientHello,
        out bool emitCertificateTypeExtension)
    {
        emitCertificateTypeExtension = false;

        if (!ExtensionList.TryFind(
                clientHello.Extensions,
                ExtensionType.ServerCertificateType,
                out HandshakeExtension extension)
            || !ServerCertificateTypeExtension.TryParseClientHello(
                extension.Data, out List<CertificateType> offered)
            || offered.Count == 0)
        {
            return CertificateType.X509;
        }

        emitCertificateTypeExtension = true;

        if (options.AllowRawPublicKeys
            && options.ServerCertificate is not null
            && offered.Contains(CertificateType.RawPublicKey))
        {
            return CertificateType.RawPublicKey;
        }

        return CertificateType.X509;
    }

    private static byte[] BuildCertificateEncryptedExtensions(
        CertificateType certificateType,
        bool emitCertificateTypeExtension)
    {
        if (!emitCertificateTypeExtension)
        {
            return EncryptedExtensions.Encode(Array.Empty<HandshakeExtension>());
        }

        return EncryptedExtensions.Encode(new[]
        {
            new HandshakeExtension(
                ExtensionType.ServerCertificateType,
                ServerCertificateTypeExtension.EncodeServerHello(certificateType)),
        });
    }

    private static SignatureScheme SelectSignatureScheme(
        ClientHello clientHello,
        X509Certificate2 certificate)
    {
        if (!ExtensionList.TryFind(
                clientHello.Extensions,
                ExtensionType.SignatureAlgorithms,
                out HandshakeExtension sigAlgExt)
            || !SignatureAlgorithmsExtension.TryParse(
                sigAlgExt.Data, out List<SignatureScheme> offered))
        {
            throw new DtlsAlertException(
                DtlsAlert.MissingExtension,
                true,
                "The ClientHello has no signature_algorithms extension.");
        }

        if (!CertificateVerifySigner.TrySelectScheme(
                certificate, offered, out SignatureScheme scheme))
        {
            throw new DtlsAlertException(
                DtlsAlert.HandshakeFailure,
                true,
                "No signature scheme is supported by both the client and the certificate.");
        }

        return scheme;
    }

    private static Dtls13CipherSuite SelectCipherSuite(
        ClientHello clientHello,
        IReadOnlyList<Dtls13CipherSuite> allowed)
    {
        // Server preference: pick the first allowed suite the client also offered.
        foreach (Dtls13CipherSuite suite in allowed)
        {
            foreach (ushort offered in clientHello.CipherSuites)
            {
                if (offered == suite.Id)
                {
                    return suite;
                }
            }
        }

        throw new DtlsAlertException(
            DtlsAlert.HandshakeFailure, true, "No mutually supported cipher suite.");
    }

    private static NamedGroup SelectGroup(ClientHello clientHello, out byte[] clientKeyShare)
    {
        if (!ExtensionList.TryFind(
                clientHello.Extensions,
                ExtensionType.SupportedGroups,
                out HandshakeExtension groupsExt)
            || !SupportedGroupsExtension.TryParse(groupsExt.Data, out List<NamedGroup> groups))
        {
            throw new DtlsAlertException(
                DtlsAlert.MissingExtension, true, "The ClientHello has no supported_groups.");
        }

        if (!ExtensionList.TryFind(
                clientHello.Extensions,
                ExtensionType.KeyShare,
                out HandshakeExtension keyShareExt)
            || !KeyShareExtension.TryParseClientHello(
                keyShareExt.Data, out List<KeyShareEntry> shares))
        {
            throw new DtlsAlertException(
                DtlsAlert.MissingExtension, true, "The ClientHello has no key_share.");
        }

        foreach (NamedGroup candidate in groups)
        {
            if (!EcdheKeyExchange.IsSupported(candidate))
            {
                continue;
            }

            foreach (KeyShareEntry entry in shares)
            {
                if (entry.Group == candidate)
                {
                    clientKeyShare = entry.KeyExchange;
                    return candidate;
                }
            }
        }

        throw new DtlsAlertException(
            DtlsAlert.HandshakeFailure, true, "No mutually supported group with a key_share.");
    }

    private static bool HasPskDheKeMode(ClientHello clientHello)
    {
        if (!ExtensionList.TryFind(
                clientHello.Extensions,
                ExtensionType.PskKeyExchangeModes,
                out HandshakeExtension modesExt)
            || !PskKeyExchangeModesExtension.TryParse(
                modesExt.Data, out List<PskKeyExchangeMode> modes))
        {
            return false;
        }

        return modes.Contains(PskKeyExchangeMode.PskDheKe);
    }

    private static ushort ResolveAndVerifyPsk(
        ClientHello clientHello,
        byte[] clientHelloBody,
        HashAlgorithmName hash,
        DtlsPskServerCallback pskCallback,
        out byte[] pskKey)
    {
        if (!ExtensionList.TryFind(
                clientHello.Extensions, ExtensionType.PreSharedKey, out HandshakeExtension pskExt)
            || !PreSharedKeyExtension.TryParseClientHello(
                pskExt.Data, out List<PskIdentity> identities, out List<byte[]> binders))
        {
            throw new DtlsAlertException(
                DtlsAlert.MissingExtension, true, "The ClientHello has no pre_shared_key.");
        }

        byte[] truncatedHash = ComputeBinderTranscriptHash(clientHelloBody, hash, binders);

        for (int i = 0; i < identities.Count; i++)
        {
            ReadOnlyMemory<byte> key = pskCallback(identities[i].Identity);
            if (key.IsEmpty)
            {
                continue;
            }

            byte[] candidateKey = key.ToArray();
            byte[] early = Dtls13KeySchedule.EarlySecret(hash, candidateKey);
            byte[] binderKey = Dtls13KeySchedule.DeriveExternalBinderKey(hash, early);
            try
            {
                if (Dtls13KeySchedule.VerifyBinder(hash, binderKey, truncatedHash, binders[i]))
                {
                    pskKey = candidateKey;
                    return (ushort)i;
                }
            }
            finally
            {
                CryptographicOperations.ZeroMemory(early);
                CryptographicOperations.ZeroMemory(binderKey);
            }

            CryptographicOperations.ZeroMemory(candidateKey);
        }

        throw new DtlsAlertException(
            DtlsAlert.DecryptError, true, "No PSK identity matched with a valid binder.");
    }

    private static byte[] ComputeBinderTranscriptHash(
        byte[] clientHelloBody,
        HashAlgorithmName hash,
        List<byte[]> binders)
    {
        byte[] transcriptBytes = HandshakeMessage.ToTranscriptBytes(
            HandshakeType.ClientHello, clientHelloBody);

        List<int> binderLengths = new(binders.Count);
        foreach (byte[] binder in binders)
        {
            binderLengths.Add(binder.Length);
        }

        int bindersBlockLength = PreSharedKeyExtension.BindersBlockLength(binderLengths);
        int truncatedLength = transcriptBytes.Length - bindersBlockLength;
        if (truncatedLength <= 0)
        {
            throw new DtlsException("The ClientHello pre_shared_key binders are malformed.");
        }

        using IncrementalHash digest = IncrementalHash.CreateHash(hash);
        digest.AppendData(transcriptBytes, 0, truncatedLength);
        return digest.GetHashAndReset();
    }

    private static byte[] BuildServerHelloBody(
        Dtls13CipherSuite suite,
        NamedGroup group,
        byte[] serverKeyShare,
        ushort selectedIdentity,
        byte[] serverConnectionId)
    {
        byte[] random = new byte[ServerHello.RandomLength];
        RandomNumberGenerator.Fill(random);

        List<HandshakeExtension> extensions = new()
        {
            new HandshakeExtension(
                ExtensionType.SupportedVersions,
                SupportedVersionsExtension.EncodeServerHello(DtlsWireVersion.Dtls13)),
            new HandshakeExtension(
                ExtensionType.KeyShare,
                KeyShareExtension.EncodeServerHello(new KeyShareEntry(group, serverKeyShare))),
            new HandshakeExtension(
                ExtensionType.PreSharedKey,
                PreSharedKeyExtension.EncodeServerHello(selectedIdentity)),
        };

        AddConnectionIdExtension(extensions, serverConnectionId);

        ServerHello serverHello = new()
        {
            Random = random,
            CipherSuite = suite.Id,
            Extensions = extensions,
        };
        return serverHello.Encode();
    }

    private static byte[] BuildCertificateServerHelloBody(
        Dtls13CipherSuite suite,
        NamedGroup group,
        byte[] serverKeyShare,
        byte[] serverConnectionId)
    {
        byte[] random = new byte[ServerHello.RandomLength];
        RandomNumberGenerator.Fill(random);

        List<HandshakeExtension> extensions = new()
        {
            new HandshakeExtension(
                ExtensionType.SupportedVersions,
                SupportedVersionsExtension.EncodeServerHello(DtlsWireVersion.Dtls13)),
            new HandshakeExtension(
                ExtensionType.KeyShare,
                KeyShareExtension.EncodeServerHello(new KeyShareEntry(group, serverKeyShare))),
        };

        AddConnectionIdExtension(extensions, serverConnectionId);

        ServerHello serverHello = new()
        {
            Random = random,
            CipherSuite = suite.Id,
            Extensions = extensions,
        };
        return serverHello.Encode();
    }

    private static void AddConnectionIdExtension(
        List<HandshakeExtension> extensions, byte[] serverConnectionId)
    {
        if (serverConnectionId.Length > 0)
        {
            extensions.Add(new HandshakeExtension(
                ExtensionType.ConnectionId, ConnectionIdExtension.Encode(serverConnectionId)));
        }
    }
}
