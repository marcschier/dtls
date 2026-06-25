using System;
using System.Collections.Generic;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Threading;
using System.Threading.Tasks;
using Dtls.Crypto;
using Dtls.Internal;
using Dtls.Protocol.V12.Handshake;
using Dtls.Transport;

namespace Dtls.Protocol.V13.Handshake;

/// <summary>
/// The managed DTLS 1.3 client handshake driver (RFC 9147 / RFC 8446). It runs either the
/// external-PSK + ECDHE (psk_dhe_ke) flow or the certificate-authenticated (EC)DHE flow,
/// selected by the configured credentials: when a <see cref="DtlsClientOptions.PskCallback"/>
/// is supplied the PSK flow is used, otherwise the certificate flow is used. It sends a
/// ClientHello, processes the server flight, and sends its own Finished.
/// </summary>
/// <remarks>
/// On the certificate path the client also answers a CertificateRequest (mutual authentication,
/// RFC 8446 section 4.3.2) and a HelloRetryRequest (cookie and/or group change, section 4.1.4).
/// Handshake flights are driven through a <see cref="Dtls13FlightTransceiver"/> that retransmits
/// on loss and de-duplicates retransmitted peer flights (RFC 9147 section 5.8); the final flight
/// is acknowledged (section 7), and messages larger than the transport MTU are fragmented and
/// reassembled (section 5.5). Deferred (not implemented here): 0-RTT. External-PSK handshakes do
/// not support HelloRetryRequest.
/// </remarks>
internal static class Dtls13ClientHandshake
{
    private static readonly SignatureScheme[] OfferedSignatureSchemes =
    {
        SignatureScheme.EcdsaSecp256r1Sha256,
        SignatureScheme.EcdsaSecp384r1Sha384,
        SignatureScheme.RsaPssRsaeSha256,
        SignatureScheme.RsaPssRsaeSha384,
    };

    // The certificate path advertises all managed (EC)DHE groups but sends a key_share only for
    // the first; the server may answer with a HelloRetryRequest selecting another (RFC 8446
    // section 4.1.4).
    private static readonly NamedGroup[] CertificateOfferedGroups =
    {
        NamedGroup.Secp256r1,
        NamedGroup.Secp384r1,
        NamedGroup.Secp521r1,
    };

    public static Task<DtlsConnection> RunAsync(
        IDatagramTransport transport,
        DtlsClientOptions options,
        CancellationToken cancellationToken,
        bool allowDtls12Fallback = false)
    {
        if (options.PskCallback is not null)
        {
            return RunPskAsync(transport, options, cancellationToken);
        }

        return RunCertificateAsync(
            transport, options, allowDtls12Fallback, cancellationToken);
    }

    private static async Task<DtlsConnection> RunPskAsync(
        IDatagramTransport transport,
        DtlsClientOptions options,
        CancellationToken cancellationToken)
    {
        PskCredential credential = options.PskCallback!(options.TargetHost);
        if (!credential.HasKey || credential.Identity.IsEmpty)
        {
            throw new DtlsException("The PSK callback did not supply an identity and key.");
        }

        // The external-PSK binder fixes the hash to SHA-256, so only SHA-256 suites are
        // offered; the resolved AEAD may still differ (AES-128-GCM, AES-CCM, AES-CCM-8).
        IReadOnlyList<Dtls13CipherSuite> offered = SelectPskCipherSuites(options);
        ushort[] offeredIds = ToCipherSuiteIds(offered);

        Dtls13CipherSuite suite = Dtls13CipherSuite.Aes128GcmSha256;
        HashAlgorithmName hash = suite.HashAlgorithm;
        const NamedGroup group = NamedGroup.Secp256r1;

        byte[] identity = credential.Identity.ToArray();
        byte[] pskKey = credential.Key.ToArray();
        List<byte[]> secrets = new() { pskKey };

        using EcdheKeyExchange ecdhe = EcdheKeyExchange.Create(group);
        Dtls13RecordProtector? recvHandshake = null;
        Dtls13RecordProtector? sendHandshake = null;
        Dtls13FlightTransceiver transceiver = new(
            transport, options.HandshakeRetransmissionTimeout, options.MaxHandshakeRetransmissions);
        try
        {
            byte[] keyShare = ecdhe.ExportKeyShare();
            byte[] random = new byte[ClientHello.RandomLength];
            RandomNumberGenerator.Fill(random);

            byte[] early = Dtls13KeySchedule.EarlySecret(hash, pskKey);
            byte[] binderKey = Dtls13KeySchedule.DeriveExternalBinderKey(hash, early);
            secrets.Add(early);
            secrets.Add(binderKey);

            byte[] clientConnectionId = NewConnectionId(options);
            byte[] clientHelloBody = BuildClientHelloBody(
                random, group, keyShare, identity, hash, binderKey, offeredIds,
                clientConnectionId);

            TranscriptHash transcript = new(hash);
            transcript.AppendMessage(HandshakeType.ClientHello, clientHelloBody);

            await Dtls13HandshakeFlight.SendPlaintextAsync(
                    transceiver, HandshakeType.ClientHello, 0, clientHelloBody, 0,
                    cancellationToken)
                .ConfigureAwait(false);

            (ServerHello serverHello, byte[] serverHelloBody) =
                await ReceiveServerHelloAsync(
                        transceiver, 0, options.MaxHandshakeMessageSize, cancellationToken)
                    .ConfigureAwait(false);
            if (serverHello.IsHelloRetryRequest)
            {
                throw new DtlsException(
                    "HelloRetryRequest is not supported with the external-PSK handshake.");
            }

            suite = ResolveServerSuite(serverHello, offered);
            transcript.AppendMessage(HandshakeType.ServerHello, serverHelloBody);

            byte[] serverKeyShare = ExtractServerKeyShare(serverHello, group);
            VerifyServerSelectedIdentity(serverHello);

            byte[] ecdheSecret = ecdhe.DeriveSharedSecret(serverKeyShare);
            secrets.Add(ecdheSecret);
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

            recvHandshake = Dtls13HandshakeRecords.CreateProtector(suite, serverHsSecret);
            sendHandshake = Dtls13HandshakeRecords.CreateProtector(suite, clientHsSecret);

            HandshakeReassembler serverFlightReassembler =
                new(options.MaxHandshakeMessageSize, firstSequence: 1);
            List<Dtls13HandshakeRecords.Message> flight = await Dtls13HandshakeFlight
                .ReceiveProtectedAsync(
                    transceiver,
                    serverFlightReassembler,
                    recvHandshake,
                    HandshakeType.Finished,
                    cancellationToken)
                .ConfigureAwait(false);

            if (flight.Count < 2
                || flight[0].Type != HandshakeType.EncryptedExtensions
                || flight[1].Type != HandshakeType.Finished)
            {
                throw new DtlsException(
                    "Expected EncryptedExtensions and Finished from the server.");
            }

            transcript.AppendMessage(HandshakeType.EncryptedExtensions, flight[0].Body);

            byte[] transcriptChEe = transcript.CurrentHash();
            if (!Dtls13KeySchedule.VerifyFinished(
                    hash, serverHsSecret, transcriptChEe, flight[1].Body))
            {
                throw new DtlsAlertException(
                    DtlsAlert.DecryptError, true, "The server Finished did not verify.");
            }

            transcript.AppendMessage(HandshakeType.Finished, flight[1].Body);

            byte[] transcriptChSf = transcript.CurrentHash();
            await SendClientFinishedAsync(
                    transceiver,
                    sendHandshake,
                    hash,
                    clientHsSecret,
                    transcriptChSf,
                    cancellationToken)
                .ConfigureAwait(false);

            await AwaitServerAckAsync(
                    transceiver, recvHandshake!, sendHandshake!, 1, cancellationToken)
                .ConfigureAwait(false);

            byte[] master = Dtls13KeySchedule.DeriveMasterSecret(hash, handshakeSecret);
            byte[] clientAp = Dtls13KeySchedule.DeriveClientApplicationTrafficSecret(
                hash, master, transcriptChSf);
            byte[] serverAp = Dtls13KeySchedule.DeriveServerApplicationTrafficSecret(
                hash, master, transcriptChSf);
            secrets.Add(master);
            secrets.Add(clientAp);
            secrets.Add(serverAp);

            return CreateClientConnection(
                transport, suite, clientAp, serverAp, clientConnectionId, serverHello);
        }
        finally
        {
            recvHandshake?.Dispose();
            sendHandshake?.Dispose();
            foreach (byte[] secret in secrets)
            {
                CryptographicOperations.ZeroMemory(secret);
            }
        }
    }

    private static async Task<DtlsConnection> RunCertificateAsync(
        IDatagramTransport transport,
        DtlsClientOptions options,
        bool allowDtls12Fallback,
        CancellationToken cancellationToken)
    {
        // Certificate mode supports hash agility: the full configured suite list (mixed
        // hashes allowed) is offered and the transcript hash is chosen after the ServerHello.
        IReadOnlyList<Dtls13CipherSuite> offered = CipherSuitePolicy.Resolve(options.CipherSuites);
        ushort[] offeredIds = ToCipherSuiteIds(offered);
        NamedGroup group = NamedGroup.Secp256r1;

        List<byte[]> secrets = new();
        EcdheKeyExchange ecdhe = EcdheKeyExchange.Create(group);
        Dtls13FlightTransceiver transceiver = new(
            transport, options.HandshakeRetransmissionTimeout, options.MaxHandshakeRetransmissions);
        try
        {
            byte[] keyShare = ecdhe.ExportKeyShare();
            byte[] random = new byte[ClientHello.RandomLength];
            RandomNumberGenerator.Fill(random);

            byte[] clientConnectionId = NewConnectionId(options);
            byte[] clientHello1Body = BuildCertificateClientHelloBody(
                random, group, keyShare, offeredIds, options.AllowRawPublicKeys,
                clientConnectionId, cookie: null, offerDtls12: allowDtls12Fallback);

            await Dtls13HandshakeFlight.SendPlaintextAsync(
                    transceiver, HandshakeType.ClientHello, 0, clientHello1Body, 0,
                    cancellationToken)
                .ConfigureAwait(false);

            // When both versions were offered, the first response is received through a
            // fallback-aware path; if the peer chose DTLS 1.2 it returns a fallback state and the
            // handshake is finished on the managed DTLS 1.2 engine.
            ServerHello serverHello;
            byte[] serverHelloBody;
            if (allowDtls12Fallback)
            {
                (serverHello, serverHelloBody, Dtls12FallbackState? fallback) =
                    await ReceiveFirstResponseWithFallbackAsync(
                            transceiver, clientHello1Body, random, options.MaxHandshakeMessageSize,
                            cancellationToken)
                        .ConfigureAwait(false);
                if (fallback is not null)
                {
                    return await Dtls12ClientHandshake
                        .ContinueFromFallbackAsync(fallback, options, cancellationToken)
                        .ConfigureAwait(false);
                }
            }
            else
            {
                (serverHello, serverHelloBody) = await ReceiveServerHelloAsync(
                        transceiver, 0, options.MaxHandshakeMessageSize, cancellationToken)
                    .ConfigureAwait(false);
            }

            byte[]? transcriptPrefix = null;
            byte[] clientHelloBody = clientHello1Body;
            if (serverHello.IsHelloRetryRequest)
            {
                ParseHelloRetryRequest(
                    serverHello, group, out NamedGroup retryGroup, out byte[] cookie);

                // Regenerate the key_share for the (possibly new) selected group.
                if (retryGroup != group)
                {
                    ecdhe.Dispose();
                    ecdhe = EcdheKeyExchange.Create(retryGroup);
                    group = retryGroup;
                    keyShare = ecdhe.ExportKeyShare();
                }

                HashAlgorithmName retryHash =
                    ResolveServerSuite(serverHello, offered).HashAlgorithm;
                byte[] clientHello1Reconstructed = HandshakeMessage.ToTranscriptBytes(
                    HandshakeType.ClientHello, clientHello1Body);
                byte[] messageHash = TranscriptHash.SynthesizeMessageHash(
                    retryHash, clientHello1Reconstructed);
                byte[] helloRetryTranscript = HandshakeMessage.ToTranscriptBytes(
                    HandshakeType.ServerHello, serverHelloBody);
                transcriptPrefix = new byte[messageHash.Length + helloRetryTranscript.Length];
                messageHash.CopyTo(transcriptPrefix, 0);
                helloRetryTranscript.CopyTo(transcriptPrefix, messageHash.Length);

                clientHelloBody = BuildCertificateClientHelloBody(
                    random, group, keyShare, offeredIds, options.AllowRawPublicKeys,
                    clientConnectionId, cookie, offerDtls12: false);
                await Dtls13HandshakeFlight.SendPlaintextAsync(
                        transceiver, HandshakeType.ClientHello, 1, clientHelloBody, 1,
                        cancellationToken)
                    .ConfigureAwait(false);

                (serverHello, serverHelloBody) =
                    await ReceiveServerHelloAsync(
                            transceiver, 0, options.MaxHandshakeMessageSize, cancellationToken)
                        .ConfigureAwait(false);
                if (serverHello.IsHelloRetryRequest)
                {
                    throw new DtlsAlertException(
                        DtlsAlert.UnexpectedMessage,
                        true,
                        "The server sent a second HelloRetryRequest.");
                }
            }

            Dtls13CipherSuite suite = ResolveServerSuite(serverHello, offered);
            HashAlgorithmName hash = suite.HashAlgorithm;

            TranscriptHash transcript = new(hash);
            if (transcriptPrefix is not null)
            {
                transcript.AppendRaw(transcriptPrefix);
            }

            transcript.AppendMessage(HandshakeType.ClientHello, clientHelloBody);
            transcript.AppendMessage(HandshakeType.ServerHello, serverHelloBody);

            byte[] serverKeyShare = ExtractServerKeyShare(serverHello, group);

            byte[] early = Dtls13KeySchedule.EarlySecret(hash, ReadOnlySpan<byte>.Empty);
            secrets.Add(early);
            byte[] ecdheSecret = ecdhe.DeriveSharedSecret(serverKeyShare);
            secrets.Add(ecdheSecret);
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

            using Dtls13RecordProtector recvHandshake = Dtls13HandshakeRecords.CreateProtector(
                suite, serverHsSecret);
            using Dtls13RecordProtector sendHandshake = Dtls13HandshakeRecords.CreateProtector(
                suite, clientHsSecret);

            HandshakeReassembler serverFlightReassembler =
                new(options.MaxHandshakeMessageSize, firstSequence: 1);
            List<Dtls13HandshakeRecords.Message> flight = await Dtls13HandshakeFlight
                .ReceiveProtectedAsync(
                    transceiver,
                    serverFlightReassembler,
                    recvHandshake,
                    HandshakeType.Finished,
                    cancellationToken)
                .ConfigureAwait(false);

            if (flight.Count < 1 || flight[0].Type != HandshakeType.EncryptedExtensions)
            {
                throw new DtlsException("Expected EncryptedExtensions from the server.");
            }

            transcript.AppendMessage(HandshakeType.EncryptedExtensions, flight[0].Body);

            int index = 1;
            List<SignatureScheme>? certificateRequestSchemes = null;
            if (index < flight.Count && flight[index].Type == HandshakeType.CertificateRequest)
            {
                if (!CertificateRequestMessage.TryParse(
                        flight[index].Body, out certificateRequestSchemes))
                {
                    throw new DtlsAlertException(
                        DtlsAlert.DecodeError,
                        true,
                        "The server CertificateRequest was malformed.");
                }

                transcript.AppendMessage(HandshakeType.CertificateRequest, flight[index].Body);
                index++;
            }

            if (flight.Count < index + 3
                || flight[index].Type != HandshakeType.Certificate
                || flight[index + 1].Type != HandshakeType.CertificateVerify
                || flight[index + 2].Type != HandshakeType.Finished)
            {
                throw new DtlsException(
                    "Expected Certificate, CertificateVerify, and Finished from the server.");
            }

            Dtls13HandshakeRecords.Message certificateRecord = flight[index];
            Dtls13HandshakeRecords.Message certificateVerifyRecord = flight[index + 1];
            Dtls13HandshakeRecords.Message serverFinishedRecord = flight[index + 2];

            CertificateType certificateType = ResolveServerCertificateType(
                options, flight[0].Body);

            if (!CertificateMessage.TryParse(
                    certificateRecord.Body, out _, out List<byte[]> certificateEntries)
                || certificateEntries.Count == 0)
            {
                throw new DtlsAlertException(
                    DtlsAlert.DecodeError, true, "The server Certificate message was malformed.");
            }

            transcript.AppendMessage(HandshakeType.Certificate, certificateRecord.Body);
            byte[] transcriptThroughCert = transcript.CurrentHash();

            if (!CertificateVerifyMessage.TryParse(
                    certificateVerifyRecord.Body, out SignatureScheme scheme, out byte[] signature))
            {
                throw new DtlsAlertException(
                    DtlsAlert.DecodeError,
                    true,
                    "The server CertificateVerify message was malformed.");
            }

            if (certificateType == CertificateType.RawPublicKey)
            {
                VerifyRawPublicKey(
                    options, certificateEntries[0], scheme, transcriptThroughCert, signature);
            }
            else
            {
                using X509Certificate2 serverCertificate = LoadCertificate(certificateEntries[0]);

                if (!CertificateVerifySigner.Verify(
                        serverCertificate, scheme, transcriptThroughCert, signature))
                {
                    throw new DtlsAlertException(
                        DtlsAlert.DecryptError,
                        true,
                        "The server CertificateVerify did not verify.");
                }

                ValidateServerCertificate(options, serverCertificate);
            }

            transcript.AppendMessage(HandshakeType.CertificateVerify, certificateVerifyRecord.Body);
            byte[] transcriptThroughCv = transcript.CurrentHash();

            if (!Dtls13KeySchedule.VerifyFinished(
                    hash, serverHsSecret, transcriptThroughCv, serverFinishedRecord.Body))
            {
                throw new DtlsAlertException(
                    DtlsAlert.DecryptError, true, "The server Finished did not verify.");
            }

            transcript.AppendMessage(HandshakeType.Finished, serverFinishedRecord.Body);

            byte[] transcriptChSf = transcript.CurrentHash();
            if (certificateRequestSchemes is not null)
            {
                await SendClientAuthFlightAsync(
                        transceiver,
                        sendHandshake,
                        hash,
                        clientHsSecret,
                        transcript,
                        options.ClientCertificates,
                        certificateRequestSchemes,
                        cancellationToken)
                    .ConfigureAwait(false);
            }
            else
            {
                await SendClientFinishedAsync(
                        transceiver,
                        sendHandshake,
                        hash,
                        clientHsSecret,
                        transcriptChSf,
                        cancellationToken)
                    .ConfigureAwait(false);
            }

            ulong clientAckSequence = certificateRequestSchemes is not null ? 3UL : 1UL;
            await AwaitServerAckAsync(
                    transceiver, recvHandshake, sendHandshake, clientAckSequence,
                    cancellationToken)
                .ConfigureAwait(false);

            byte[] master = Dtls13KeySchedule.DeriveMasterSecret(hash, handshakeSecret);
            byte[] clientAp = Dtls13KeySchedule.DeriveClientApplicationTrafficSecret(
                hash, master, transcriptChSf);
            byte[] serverAp = Dtls13KeySchedule.DeriveServerApplicationTrafficSecret(
                hash, master, transcriptChSf);
            secrets.Add(master);
            secrets.Add(clientAp);
            secrets.Add(serverAp);

            return CreateClientConnection(
                transport, suite, clientAp, serverAp, clientConnectionId, serverHello);
        }
        finally
        {
            ecdhe.Dispose();
            foreach (byte[] secret in secrets)
            {
                CryptographicOperations.ZeroMemory(secret);
            }
        }
    }

    private static void ParseHelloRetryRequest(
        ServerHello helloRetryRequest,
        NamedGroup originalKeyShareGroup,
        out NamedGroup selectedGroup,
        out byte[] cookie)
    {
        selectedGroup = originalKeyShareGroup;
        cookie = Array.Empty<byte>();
        bool changesClientHello = false;

        if (ExtensionList.TryFind(
                helloRetryRequest.Extensions,
                ExtensionType.KeyShare,
                out HandshakeExtension keyShareExt))
        {
            if (!KeyShareExtension.TryParseHelloRetryRequest(
                    keyShareExt.Data, out NamedGroup requested))
            {
                throw new DtlsAlertException(
                    DtlsAlert.DecodeError,
                    true,
                    "The HelloRetryRequest key_share was malformed.");
            }

            bool wasOffered = false;
            foreach (NamedGroup candidate in CertificateOfferedGroups)
            {
                if (candidate == requested)
                {
                    wasOffered = true;
                    break;
                }
            }

            // RFC 8446 section 4.1.4: the selected group must have been offered and must differ
            // from a group already in the original key_share.
            if (!wasOffered
                || !EcdheKeyExchange.IsSupported(requested)
                || requested == originalKeyShareGroup)
            {
                throw new DtlsAlertException(
                    DtlsAlert.IllegalParameter,
                    true,
                    "The HelloRetryRequest selected an invalid group.");
            }

            selectedGroup = requested;
            changesClientHello = true;
        }

        if (ExtensionList.TryFind(
                helloRetryRequest.Extensions,
                ExtensionType.Cookie,
                out HandshakeExtension cookieExt))
        {
            if (!CookieExtension.TryParse(cookieExt.Data, out cookie))
            {
                throw new DtlsAlertException(
                    DtlsAlert.DecodeError,
                    true,
                    "The HelloRetryRequest cookie was malformed.");
            }

            changesClientHello = true;
        }

        if (!changesClientHello)
        {
            throw new DtlsAlertException(
                DtlsAlert.IllegalParameter,
                true,
                "The HelloRetryRequest would not change the ClientHello.");
        }
    }

    private static async Task<(ServerHello Hello, byte[] Body)> ReceiveServerHelloAsync(
        Dtls13FlightTransceiver transceiver,
        ushort firstSequence,
        int maxHandshakeMessageSize,
        CancellationToken cancellationToken)
    {
        // The ServerHello / HelloRetryRequest is reassembled from its plaintext epoch-0 fragments.
        // Over a lossy transport the protected epoch-2 server flight may arrive before it; those
        // datagrams carry no plaintext handshake fragment, so ReceivePlaintextHandshakeAsync
        // forgets them (the transceiver redelivers them to the flight receive that needs them).
        (HandshakeType type, byte[] body) = await Dtls13HandshakeFlight
            .ReceivePlaintextHandshakeAsync(
                transceiver, firstSequence, maxHandshakeMessageSize, cancellationToken)
            .ConfigureAwait(false);

        if (type != HandshakeType.ServerHello
            || !ServerHello.TryParse(body, out ServerHello serverHello))
        {
            throw new DtlsException("Expected a ServerHello but received a malformed record.");
        }

        return (serverHello, body);
    }

    // Receives the first server response when both DTLS 1.3 and 1.2 were offered. Returns the
    // parsed ServerHello (and a null fallback) when the server selected DTLS 1.3; returns a
    // Dtls12FallbackState (carrying the live transceiver state) when the server selected DTLS 1.2 —
    // either via a HelloVerifyRequest or by replying with its DTLS 1.2 hello flight directly.
    private static async Task<(ServerHello Hello, byte[] Body, Dtls12FallbackState? Fallback)>
        ReceiveFirstResponseWithFallbackAsync(
            Dtls13FlightTransceiver transceiver,
            byte[] clientHelloBody,
            byte[] random,
            int maxHandshakeMessageSize,
            CancellationToken cancellationToken)
    {
        HandshakeReassembler reassembler = new(maxHandshakeMessageSize, firstSequence: 0);
        List<Dtls13HandshakeRecords.Message> drained = new();
        bool collecting12 = false;
        while (true)
        {
            byte[] datagram = await transceiver.ReceiveFlightAsync(cancellationToken)
                .ConfigureAwait(false);
            bool offered = Dtls13HandshakeFlight.OfferPlaintext(datagram, reassembler);

            while (reassembler.TryReadNext(
                out HandshakeType type, out byte[] body, out ushort sequence))
            {
                drained.Add(new Dtls13HandshakeRecords.Message(type, body, sequence));

                if (!collecting12)
                {
                    if (type == HandshakeType.HelloVerifyRequest)
                    {
                        if (!Dtls12HelloVerifyRequest.TryParse(body, out byte[] cookie))
                        {
                            throw new DtlsException("Malformed HelloVerifyRequest.");
                        }

                        return (new ServerHello(), Array.Empty<byte>(), new Dtls12FallbackState(
                            transceiver, clientHelloBody, random, 1, cookie, null));
                    }

                    if (type != HandshakeType.ServerHello)
                    {
                        throw new DtlsException(
                            "Expected a ServerHello or HelloVerifyRequest.");
                    }

                    if (ServerHello.TryParse(body, out ServerHello serverHello)
                        && ExtensionList.TryFind(
                            serverHello.Extensions, ExtensionType.SupportedVersions, out _))
                    {
                        return (serverHello, body, null); // The server selected DTLS 1.3.
                    }

                    collecting12 = true; // The server selected DTLS 1.2; collect its flight.
                }

                if (collecting12 && type == HandshakeType.ServerHelloDone)
                {
                    return (new ServerHello(), Array.Empty<byte>(), new Dtls12FallbackState(
                        transceiver, clientHelloBody, random, 1, null, drained));
                }
            }

            if (!offered && !collecting12)
            {
                // A datagram with no plaintext handshake fragment (an early protected flight over a
                // lossy transport): forget it so a later receive can consume it.
                transceiver.Forget(datagram);
            }
        }
    }

    private static Dtls13CipherSuite ResolveServerSuite(
        ServerHello serverHello,
        IReadOnlyList<Dtls13CipherSuite> offered)
    {
        if (!Dtls13CipherSuite.TryGet(serverHello.CipherSuite, out Dtls13CipherSuite suite))
        {
            throw new DtlsException("The server selected an unsupported cipher suite.");
        }

        foreach (Dtls13CipherSuite candidate in offered)
        {
            if (candidate.Id == suite.Id)
            {
                return suite;
            }
        }

        throw new DtlsException("The server selected a cipher suite that was not offered.");
    }

    private static List<Dtls13CipherSuite> SelectPskCipherSuites(DtlsClientOptions options)
    {
        List<Dtls13CipherSuite> sha256 = new();
        foreach (Dtls13CipherSuite suite in CipherSuitePolicy.Resolve(options.CipherSuites))
        {
            if (suite.HashAlgorithm == HashAlgorithmName.SHA256)
            {
                sha256.Add(suite);
            }
        }

        if (sha256.Count == 0)
        {
            throw new DtlsException(
                "External-PSK handshakes require a SHA-256 cipher suite, but none were "
                + "configured (AES-256-GCM uses SHA-384).");
        }

        return sha256;
    }

    private static ushort[] ToCipherSuiteIds(IReadOnlyList<Dtls13CipherSuite> suites)
    {
        ushort[] ids = new ushort[suites.Count];
        for (int i = 0; i < suites.Count; i++)
        {
            ids[i] = suites[i].Id;
        }

        return ids;
    }

    private static async Task SendClientFinishedAsync(
        Dtls13FlightTransceiver transceiver,
        Dtls13RecordProtector sendHandshake,
        HashAlgorithmName hash,
        byte[] clientHsSecret,
        byte[] transcriptChSf,
        CancellationToken cancellationToken)
    {
        byte[] clientFinished = Dtls13KeySchedule.ComputeVerifyData(
            hash, clientHsSecret, transcriptChSf);
        List<OutboundHandshakeMessage> flightMessages = new()
        {
            new OutboundHandshakeMessage(HandshakeType.Finished, 1, clientFinished),
        };

        (List<byte[]> datagrams, _) = Dtls13HandshakeFlight.BuildProtected(
            flightMessages, sendHandshake, transceiver.Transport.MaxDatagramSize, 0);
        foreach (byte[] datagram in datagrams)
        {
            await transceiver.SendAsync(datagram, cancellationToken).ConfigureAwait(false);
        }
    }

    // Waits for the server's ACK of the client's final flight (RFC 9147 section 7), so a lost
    // client Finished is retransmitted by the transceiver, then acknowledges that ACK so the
    // server completes without lingering. Any record that is not the ACK (for example a
    // retransmitted server flight) is consumed and the wait continues.
    private static async Task AwaitServerAckAsync(
        Dtls13FlightTransceiver transceiver,
        Dtls13RecordProtector recvHandshake,
        Dtls13RecordProtector sendHandshake,
        ulong ackSequence,
        CancellationToken cancellationToken)
    {
        while (true)
        {
            byte[] datagram = await transceiver.ReceiveFlightAsync(cancellationToken)
                .ConfigureAwait(false);
            if (Dtls13HandshakeRecords.ContainsAck(datagram, recvHandshake))
            {
                byte[] ackOfAck = Dtls13HandshakeRecords.SealAckRecord(
                    sendHandshake, ackSequence, new[] { new RecordNumber(2, 0) });
                await transceiver.SendAsync(ackOfAck, cancellationToken).ConfigureAwait(false);
                return;
            }
        }
    }

    private static async Task SendClientAuthFlightAsync(
        Dtls13FlightTransceiver transceiver,
        Dtls13RecordProtector sendHandshake,
        HashAlgorithmName hash,
        byte[] clientHsSecret,
        TranscriptHash transcript,
        X509Certificate2Collection clientCertificates,
        List<SignatureScheme> requestedSchemes,
        CancellationToken cancellationToken)
    {
        X509Certificate2? clientCertificate = SelectClientCertificate(
            clientCertificates, requestedSchemes, out SignatureScheme scheme);

        List<OutboundHandshakeMessage> messages = new();
        ushort messageSequence = 1;

        if (clientCertificate is not null)
        {
            byte[] certificateBody = CertificateMessage.Encode(new[] { clientCertificate.RawData });
            transcript.AppendMessage(HandshakeType.Certificate, certificateBody);
            byte[] transcriptThroughCert = transcript.CurrentHash();

            byte[] signature = CertificateVerifySigner.Sign(
                clientCertificate, scheme, transcriptThroughCert, clientContext: true);
            byte[] certificateVerifyBody = CertificateVerifyMessage.Encode(scheme, signature);
            transcript.AppendMessage(HandshakeType.CertificateVerify, certificateVerifyBody);

            messages.Add(new OutboundHandshakeMessage(
                HandshakeType.Certificate, messageSequence++, certificateBody));
            messages.Add(new OutboundHandshakeMessage(
                HandshakeType.CertificateVerify, messageSequence++, certificateVerifyBody));
        }
        else
        {
            // No suitable client certificate: send an empty Certificate (the server decides
            // whether to fail based on its RequireClientCertificate setting).
            byte[] certificateBody = CertificateMessage.Encode(Array.Empty<byte[]>());
            transcript.AppendMessage(HandshakeType.Certificate, certificateBody);
            messages.Add(new OutboundHandshakeMessage(
                HandshakeType.Certificate, messageSequence++, certificateBody));
        }

        byte[] transcriptThroughClientAuth = transcript.CurrentHash();
        byte[] clientFinished = Dtls13KeySchedule.ComputeVerifyData(
            hash, clientHsSecret, transcriptThroughClientAuth);
        messages.Add(new OutboundHandshakeMessage(
            HandshakeType.Finished, messageSequence, clientFinished));

        (List<byte[]> datagrams, _) = Dtls13HandshakeFlight.BuildProtected(
            messages, sendHandshake, transceiver.Transport.MaxDatagramSize, 0);
        foreach (byte[] datagram in datagrams)
        {
            await transceiver.SendAsync(datagram, cancellationToken).ConfigureAwait(false);
        }
    }

    private static X509Certificate2? SelectClientCertificate(
        X509Certificate2Collection clientCertificates,
        List<SignatureScheme> requestedSchemes,
        out SignatureScheme scheme)
    {
        scheme = default;
        foreach (X509Certificate2 certificate in clientCertificates)
        {
            if (certificate.HasPrivateKey
                && CertificateVerifySigner.TrySelectScheme(
                    certificate, requestedSchemes, out scheme))
            {
                return certificate;
            }
        }

        return null;
    }

    private static CertificateType ResolveServerCertificateType(
        DtlsClientOptions options,
        byte[] encryptedExtensionsBody)
    {
        if (!EncryptedExtensions.TryParse(
                encryptedExtensionsBody, out List<HandshakeExtension> extensions))
        {
            throw new DtlsAlertException(
                DtlsAlert.DecodeError, true, "The server EncryptedExtensions were malformed.");
        }

        if (!ExtensionList.TryFind(
                extensions, ExtensionType.ServerCertificateType, out HandshakeExtension extension))
        {
            return CertificateType.X509;
        }

        if (!ServerCertificateTypeExtension.TryParseServerHello(
                extension.Data, out CertificateType selected))
        {
            throw new DtlsAlertException(
                DtlsAlert.DecodeError,
                true,
                "The server server_certificate_type extension was malformed.");
        }

        if (selected == CertificateType.RawPublicKey && !options.AllowRawPublicKeys)
        {
            throw new DtlsAlertException(
                DtlsAlert.UnsupportedExtension,
                true,
                "The server selected a raw public key that was not offered.");
        }

        return selected;
    }

    private static void VerifyRawPublicKey(
        DtlsClientOptions options,
        byte[] subjectPublicKeyInfo,
        SignatureScheme scheme,
        byte[] transcriptThroughCert,
        byte[] signature)
    {
        if (options.RawPublicKeyValidation is null
            || !options.RawPublicKeyValidation(subjectPublicKeyInfo))
        {
            throw new DtlsAlertException(
                DtlsAlert.BadCertificate,
                true,
                "The server raw public key was rejected by RawPublicKeyValidation.");
        }

        using AsymmetricAlgorithm publicKey = RawPublicKey.ImportSubjectPublicKeyInfo(
            subjectPublicKeyInfo);

        if (!CertificateVerifySigner.Verify(
                publicKey, scheme, transcriptThroughCert, signature))
        {
            throw new DtlsAlertException(
                DtlsAlert.DecryptError, true, "The server CertificateVerify did not verify.");
        }
    }

    private static void ValidateServerCertificate(
        DtlsClientOptions options,
        X509Certificate2 certificate)
    {
        bool nameValidationFailed = false;
        if (!string.IsNullOrEmpty(options.TargetHost))
        {
#if NET8_0_OR_GREATER
            nameValidationFailed = !certificate.MatchesHostname(options.TargetHost!);
#else
            nameValidationFailed = true;
#endif
        }

        using X509Chain chain = new();
        chain.ChainPolicy.RevocationMode = X509RevocationMode.NoCheck;
        bool chainBuilt = chain.Build(certificate);

        if (options.RemoteCertificateValidation is not null)
        {
            if (!options.RemoteCertificateValidation(certificate, chain, nameValidationFailed))
            {
                throw new DtlsAlertException(
                    DtlsAlert.BadCertificate,
                    true,
                    "The server certificate was rejected by RemoteCertificateValidation.");
            }

            return;
        }

        if (!chainBuilt || nameValidationFailed)
        {
            throw new DtlsAlertException(
                DtlsAlert.BadCertificate,
                true,
                "The server certificate failed default chain or name validation.");
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

    private static byte[] BuildClientHelloBody(
        byte[] random,
        NamedGroup group,
        byte[] keyShare,
        byte[] identity,
        HashAlgorithmName hash,
        byte[] binderKey,
        ushort[] offeredIds,
        byte[] connectionId)
    {
        int hashLength = Hkdf.HashLength(hash);
        byte[] placeholder = new byte[hashLength];
        byte[] bodyWithPlaceholder = EncodeClientHelloBody(
            random, group, keyShare, identity, placeholder, offeredIds, connectionId);

        byte[] transcriptBytes = HandshakeMessage.ToTranscriptBytes(
            HandshakeType.ClientHello, bodyWithPlaceholder);
        int bindersBlockLength = PreSharedKeyExtension.BindersBlockLength(
            new[] { hashLength });
        int truncatedLength = transcriptBytes.Length - bindersBlockLength;

        byte[] truncatedHash;
        using (IncrementalHash digest = IncrementalHash.CreateHash(hash))
        {
            digest.AppendData(transcriptBytes, 0, truncatedLength);
            truncatedHash = digest.GetHashAndReset();
        }

        byte[] binder = Dtls13KeySchedule.ComputeBinder(hash, binderKey, truncatedHash);
        return EncodeClientHelloBody(
            random, group, keyShare, identity, binder, offeredIds, connectionId);
    }

    private static byte[] EncodeClientHelloBody(
        byte[] random,
        NamedGroup group,
        byte[] keyShare,
        byte[] identity,
        byte[] binder,
        ushort[] offeredIds,
        byte[] connectionId)
    {
        List<HandshakeExtension> extensions = new()
        {
            new HandshakeExtension(
                ExtensionType.SupportedVersions,
                SupportedVersionsExtension.EncodeClientHello(
                    new ushort[] { DtlsWireVersion.Dtls13 })),
            new HandshakeExtension(
                ExtensionType.SupportedGroups,
                SupportedGroupsExtension.Encode(new[] { group })),
            new HandshakeExtension(
                ExtensionType.KeyShare,
                KeyShareExtension.EncodeClientHello(
                    new[] { new KeyShareEntry(group, keyShare) })),
            new HandshakeExtension(
                ExtensionType.PskKeyExchangeModes,
                PskKeyExchangeModesExtension.Encode(
                    new[] { PskKeyExchangeMode.PskDheKe })),
        };

        if (connectionId.Length > 0)
        {
            extensions.Add(new HandshakeExtension(
                ExtensionType.ConnectionId, ConnectionIdExtension.Encode(connectionId)));
        }

        // pre_shared_key must be the last extension (RFC 8446 section 4.2.11).
        extensions.Add(new HandshakeExtension(
            ExtensionType.PreSharedKey,
            PreSharedKeyExtension.EncodeClientHello(
                new[] { new PskIdentity(identity, 0) },
                new[] { binder })));

        ClientHello clientHello = new()
        {
            Random = random,
            CipherSuites = offeredIds,
            Extensions = extensions,
        };
        return clientHello.Encode();
    }

    private static byte[] BuildCertificateClientHelloBody(
        byte[] random,
        NamedGroup group,
        byte[] keyShare,
        ushort[] offeredIds,
        bool offerRawPublicKey,
        byte[] connectionId,
        byte[]? cookie,
        bool offerDtls12)
    {
        ushort[] supportedVersions = offerDtls12
            ? new ushort[] { DtlsWireVersion.Dtls13, DtlsWireVersion.Dtls12 }
            : new ushort[] { DtlsWireVersion.Dtls13 };

        List<HandshakeExtension> extensions = new()
        {
            new HandshakeExtension(
                ExtensionType.SupportedVersions,
                SupportedVersionsExtension.EncodeClientHello(supportedVersions)),
            new HandshakeExtension(
                ExtensionType.SupportedGroups,
                SupportedGroupsExtension.Encode(CertificateOfferedGroups)),
            new HandshakeExtension(
                ExtensionType.KeyShare,
                KeyShareExtension.EncodeClientHello(
                    new[] { new KeyShareEntry(group, keyShare) })),
            new HandshakeExtension(
                ExtensionType.SignatureAlgorithms,
                SignatureAlgorithmsExtension.Encode(OfferedSignatureSchemes)),
        };

        ushort[] cipherSuites = offeredIds;
        if (offerDtls12)
        {
            // Add the DTLS 1.2 certificate cipher suites and the DTLS 1.2 ClientHello extensions so
            // a DTLS 1.2-only peer can complete the handshake; a DTLS 1.3 peer ignores them.
            IReadOnlyList<ushort> dtls12Ids = Dtls12CipherSuite.DefaultIdsFor(
                certificate: true, ecdhePsk: false, plainPsk: false);
            cipherSuites = new ushort[offeredIds.Length + dtls12Ids.Count];
            offeredIds.CopyTo(cipherSuites, 0);
            for (int i = 0; i < dtls12Ids.Count; i++)
            {
                cipherSuites[offeredIds.Length + i] = dtls12Ids[i];
            }

            extensions.Add(new HandshakeExtension(
                ExtensionType.EcPointFormats, Dtls12Extensions.EncodeEcPointFormats()));
            extensions.Add(new HandshakeExtension(
                ExtensionType.ExtendedMasterSecret,
                Dtls12Extensions.EncodeExtendedMasterSecret()));
            extensions.Add(new HandshakeExtension(
                ExtensionType.RenegotiationInfo, Dtls12Extensions.EncodeRenegotiationInfo()));
        }

        if (offerRawPublicKey)
        {
            extensions.Add(new HandshakeExtension(
                ExtensionType.ServerCertificateType,
                ServerCertificateTypeExtension.EncodeClientHello(
                    new[] { CertificateType.RawPublicKey, CertificateType.X509 })));
        }

        if (cookie is { Length: > 0 })
        {
            extensions.Add(new HandshakeExtension(
                ExtensionType.Cookie, CookieExtension.Encode(cookie)));
        }

        if (connectionId.Length > 0)
        {
            extensions.Add(new HandshakeExtension(
                ExtensionType.ConnectionId, ConnectionIdExtension.Encode(connectionId)));
        }

        ClientHello clientHello = new()
        {
            Random = random,
            CipherSuites = cipherSuites,
            Extensions = extensions,
        };
        return clientHello.Encode();
    }

    private static byte[] NewConnectionId(DtlsOptions options)
    {
        if (!options.UseConnectionId)
        {
            return Array.Empty<byte>();
        }

        byte[] cid = new byte[8];
        RandomNumberGenerator.Fill(cid);
        return cid;
    }

    private static byte[]? ExtractConnectionId(ServerHello serverHello)
    {
        if (serverHello.Extensions is { } extensions
            && ExtensionList.TryFind(
                extensions, ExtensionType.ConnectionId, out HandshakeExtension extension)
            && ConnectionIdExtension.TryParse(extension.Data, out byte[] cid))
        {
            return cid;
        }

        return null;
    }

    private static Dtls13Connection CreateClientConnection(
        IDatagramTransport transport,
        Dtls13CipherSuite suite,
        byte[] clientApplicationSecret,
        byte[] serverApplicationSecret,
        byte[] clientConnectionId,
        ServerHello serverHello)
    {
        byte[]? serverConnectionId = ExtractConnectionId(serverHello);
        if (clientConnectionId.Length > 0 && serverConnectionId is not null)
        {
            return Dtls13Connection.Create(
                transport,
                suite,
                clientApplicationSecret,
                serverApplicationSecret,
                sendConnectionId: serverConnectionId,
                receiveConnectionIdLength: clientConnectionId.Length);
        }

        return Dtls13Connection.Create(
            transport, suite, clientApplicationSecret, serverApplicationSecret);
    }

    private static byte[] ExtractServerKeyShare(ServerHello serverHello, NamedGroup expectedGroup)
    {
        if (!ExtensionList.TryFind(
                serverHello.Extensions, ExtensionType.KeyShare, out HandshakeExtension keyShare)
            || !KeyShareExtension.TryParseServerHello(keyShare.Data, out KeyShareEntry entry)
            || entry.Group != expectedGroup)
        {
            throw new DtlsException("The ServerHello key_share is missing or for the wrong group.");
        }

        return entry.KeyExchange;
    }

    private static void VerifyServerSelectedIdentity(ServerHello serverHello)
    {
        if (!ExtensionList.TryFind(
                serverHello.Extensions, ExtensionType.PreSharedKey, out HandshakeExtension psk)
            || !PreSharedKeyExtension.TryParseServerHello(psk.Data, out ushort selectedIdentity)
            || selectedIdentity != 0)
        {
            throw new DtlsException("The server did not accept the offered pre_shared_key.");
        }
    }
}
