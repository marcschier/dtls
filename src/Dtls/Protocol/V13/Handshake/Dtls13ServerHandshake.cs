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
/// Deferred (not implemented here): HelloRetryRequest cookies, mutual (client) certificate
/// authentication, handshake fragmentation across datagrams, retransmission, Connection ID,
/// KeyUpdate, and 0-RTT.
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

        if (UseCertificate(options, clientHello))
        {
            CertificateType certificateType = SelectServerCertificateType(
                options, clientHello, out bool emitCertificateTypeExtension);

            return await RunCertificateAsync(
                    transport,
                    options.ServerCertificate!,
                    clientHello,
                    clientHelloBody,
                    suite,
                    hash,
                    group,
                    clientKeyShare,
                    certificateType,
                    emitCertificateTypeExtension,
                    cancellationToken)
                .ConfigureAwait(false);
        }

        return await RunPskAsync(
                transport,
                options.PskCallback!,
                clientHello,
                clientHelloBody,
                suite,
                hash,
                group,
                clientKeyShare,
                cancellationToken)
            .ConfigureAwait(false);
    }

    private static async Task<DtlsConnection> RunPskAsync(
        IDatagramTransport transport,
        DtlsPskServerCallback pskCallback,
        ClientHello clientHello,
        byte[] clientHelloBody,
        Dtls13CipherSuite suite,
        HashAlgorithmName hash,
        NamedGroup group,
        byte[] clientKeyShare,
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
                suite, group, serverKeyShare, selectedIdentity);
            transcript.AppendMessage(HandshakeType.ServerHello, serverHelloBody);

            byte[] serverHelloMessage = HandshakeMessage.Serialize(
                HandshakeType.ServerHello, 0, serverHelloBody);
            byte[] serverHelloRecord = Dtls13PlaintextRecord.Encode(
                Dtls13PlaintextRecord.HandshakeContentType, 0, 0, serverHelloMessage);
            await transport.SendAsync(serverHelloRecord, cancellationToken).ConfigureAwait(false);

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
            await transport.SendAsync(flight, cancellationToken).ConfigureAwait(false);

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
                    transport,
                    recvHandshake,
                    hash,
                    clientHsSecret,
                    transcriptChSf,
                    cancellationToken)
                .ConfigureAwait(false);

            return Dtls13Connection.Create(transport, suite, serverAp, clientAp);
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
        IDatagramTransport transport,
        X509Certificate2 certificate,
        ClientHello clientHello,
        byte[] clientHelloBody,
        Dtls13CipherSuite suite,
        HashAlgorithmName hash,
        NamedGroup group,
        byte[] clientKeyShare,
        CertificateType certificateType,
        bool emitCertificateTypeExtension,
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
            transcript.AppendMessage(HandshakeType.ClientHello, clientHelloBody);

            byte[] early = Dtls13KeySchedule.EarlySecret(hash, ReadOnlySpan<byte>.Empty);
            secrets.Add(early);

            byte[] serverKeyShare = ecdhe.ExportKeyShare();
            byte[] ecdheSecret = ecdhe.DeriveSharedSecret(clientKeyShare);
            secrets.Add(ecdheSecret);

            byte[] serverHelloBody = BuildCertificateServerHelloBody(suite, group, serverKeyShare);
            transcript.AppendMessage(HandshakeType.ServerHello, serverHelloBody);

            byte[] serverHelloMessage = HandshakeMessage.Serialize(
                HandshakeType.ServerHello, 0, serverHelloBody);
            byte[] serverHelloRecord = Dtls13PlaintextRecord.Encode(
                Dtls13PlaintextRecord.HandshakeContentType, 0, 0, serverHelloMessage);
            await transport.SendAsync(serverHelloRecord, cancellationToken).ConfigureAwait(false);

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
                certificateBody,
                certificateVerifyBody,
                serverFinished);
            await transport.SendAsync(flight, cancellationToken).ConfigureAwait(false);

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
                    transport,
                    recvHandshake,
                    hash,
                    clientHsSecret,
                    transcriptChSf,
                    cancellationToken)
                .ConfigureAwait(false);

            return Dtls13Connection.Create(transport, suite, serverAp, clientAp);
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
        byte[] certificateBody,
        byte[] certificateVerifyBody,
        byte[] serverFinished)
    {
        byte[] eeMessage = HandshakeMessage.Serialize(
            HandshakeType.EncryptedExtensions, 1, encryptedExtensionsBody);
        byte[] certificateMessage = HandshakeMessage.Serialize(
            HandshakeType.Certificate, 2, certificateBody);
        byte[] certificateVerifyMessage = HandshakeMessage.Serialize(
            HandshakeType.CertificateVerify, 3, certificateVerifyBody);
        byte[] finishedMessage = HandshakeMessage.Serialize(
            HandshakeType.Finished, 4, serverFinished);

        byte[] eeRecord = Dtls13HandshakeRecords.SealHandshakeRecord(protector, 0, eeMessage);
        byte[] certificateRecord = Dtls13HandshakeRecords.SealHandshakeRecord(
            protector, 1, certificateMessage);
        byte[] certificateVerifyRecord = Dtls13HandshakeRecords.SealHandshakeRecord(
            protector, 2, certificateVerifyMessage);
        byte[] finishedRecord = Dtls13HandshakeRecords.SealHandshakeRecord(
            protector, 3, finishedMessage);

        byte[] flight = new byte[eeRecord.Length + certificateRecord.Length
            + certificateVerifyRecord.Length + finishedRecord.Length];
        int offset = 0;
        eeRecord.CopyTo(flight, offset);
        offset += eeRecord.Length;
        certificateRecord.CopyTo(flight, offset);
        offset += certificateRecord.Length;
        certificateVerifyRecord.CopyTo(flight, offset);
        offset += certificateVerifyRecord.Length;
        finishedRecord.CopyTo(flight, offset);
        return flight;
    }

    private static async Task ReceiveAndVerifyClientFinishedAsync(
        IDatagramTransport transport,
        Dtls13RecordProtector recvHandshake,
        HashAlgorithmName hash,
        byte[] clientHsSecret,
        byte[] transcriptChSf,
        CancellationToken cancellationToken)
    {
        byte[] finishedDatagram = await ReceiveDatagramAsync(transport, cancellationToken)
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
        ushort selectedIdentity)
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
        byte[] serverKeyShare)
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

        ServerHello serverHello = new()
        {
            Random = random,
            CipherSuite = suite.Id,
            Extensions = extensions,
        };
        return serverHello.Encode();
    }

    private static async Task<byte[]> ReceiveDatagramAsync(
        IDatagramTransport transport,
        CancellationToken cancellationToken)
    {
        byte[] buffer = new byte[transport.MaxDatagramSize];
        int received = await transport.ReceiveAsync(buffer, cancellationToken)
            .ConfigureAwait(false);
        if (received == 0)
        {
            throw new DtlsException("The peer closed the transport during the handshake.");
        }

        return buffer.AsSpan(0, received).ToArray();
    }
}
