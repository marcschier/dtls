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
/// The managed DTLS 1.3 client handshake driver (RFC 9147 / RFC 8446). It runs either the
/// external-PSK + ECDHE (psk_dhe_ke) flow or the certificate-authenticated (EC)DHE flow,
/// selected by the configured credentials: when a <see cref="DtlsClientOptions.PskCallback"/>
/// is supplied the PSK flow is used, otherwise the certificate flow is used. It sends a
/// ClientHello, processes the server flight, and sends its own Finished.
/// </summary>
/// <remarks>
/// Deferred (not implemented here): HelloRetryRequest cookies, client (mutual) certificate
/// authentication, handshake fragmentation across datagrams, retransmission, Connection ID,
/// KeyUpdate, and 0-RTT.
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

    public static Task<DtlsConnection> RunAsync(
        IDatagramTransport transport,
        DtlsClientOptions options,
        CancellationToken cancellationToken)
    {
        if (options.PskCallback is not null)
        {
            return RunPskAsync(transport, options, cancellationToken);
        }

        return RunCertificateAsync(transport, options, cancellationToken);
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

            byte[] clientHelloMessage = HandshakeMessage.Serialize(
                HandshakeType.ClientHello, 0, clientHelloBody);
            byte[] clientHelloRecord = Dtls13PlaintextRecord.Encode(
                Dtls13PlaintextRecord.HandshakeContentType, 0, 0, clientHelloMessage);
            await transport.SendAsync(clientHelloRecord, cancellationToken).ConfigureAwait(false);

            (ServerHello serverHello, byte[] serverHelloBody) =
                await ReceiveServerHelloAsync(transport, cancellationToken).ConfigureAwait(false);
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

            byte[] flightDatagram = await ReceiveDatagramAsync(transport, cancellationToken)
                .ConfigureAwait(false);
            List<Dtls13HandshakeRecords.Message> flight =
                Dtls13HandshakeRecords.OpenHandshakeFlight(flightDatagram, recvHandshake);

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
                    transport,
                    sendHandshake,
                    hash,
                    clientHsSecret,
                    transcriptChSf,
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
        CancellationToken cancellationToken)
    {
        // Certificate mode supports hash agility: the full configured suite list (mixed
        // hashes allowed) is offered and the transcript hash is chosen after the ServerHello.
        IReadOnlyList<Dtls13CipherSuite> offered = CipherSuitePolicy.Resolve(options.CipherSuites);
        ushort[] offeredIds = ToCipherSuiteIds(offered);
        const NamedGroup group = NamedGroup.Secp256r1;

        List<byte[]> secrets = new();
        using EcdheKeyExchange ecdhe = EcdheKeyExchange.Create(group);
        try
        {
            byte[] keyShare = ecdhe.ExportKeyShare();
            byte[] random = new byte[ClientHello.RandomLength];
            RandomNumberGenerator.Fill(random);

            byte[] clientConnectionId = NewConnectionId(options);
            byte[] clientHelloBody = BuildCertificateClientHelloBody(
                random, group, keyShare, offeredIds, options.AllowRawPublicKeys,
                clientConnectionId);

            byte[] clientHelloMessage = HandshakeMessage.Serialize(
                HandshakeType.ClientHello, 0, clientHelloBody);
            byte[] clientHelloRecord = Dtls13PlaintextRecord.Encode(
                Dtls13PlaintextRecord.HandshakeContentType, 0, 0, clientHelloMessage);
            await transport.SendAsync(clientHelloRecord, cancellationToken).ConfigureAwait(false);

            (ServerHello serverHello, byte[] serverHelloBody) =
                await ReceiveServerHelloAsync(transport, cancellationToken).ConfigureAwait(false);
            Dtls13CipherSuite suite = ResolveServerSuite(serverHello, offered);
            HashAlgorithmName hash = suite.HashAlgorithm;

            TranscriptHash transcript = new(hash);
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

            byte[] flightDatagram = await ReceiveDatagramAsync(transport, cancellationToken)
                .ConfigureAwait(false);
            List<Dtls13HandshakeRecords.Message> flight =
                Dtls13HandshakeRecords.OpenHandshakeFlight(flightDatagram, recvHandshake);

            if (flight.Count < 4
                || flight[0].Type != HandshakeType.EncryptedExtensions
                || flight[1].Type != HandshakeType.Certificate
                || flight[2].Type != HandshakeType.CertificateVerify
                || flight[3].Type != HandshakeType.Finished)
            {
                throw new DtlsException(
                    "Expected EncryptedExtensions, Certificate, CertificateVerify, and "
                    + "Finished from the server.");
            }

            transcript.AppendMessage(HandshakeType.EncryptedExtensions, flight[0].Body);

            CertificateType certificateType = ResolveServerCertificateType(
                options, flight[0].Body);

            if (!CertificateMessage.TryParse(
                    flight[1].Body, out _, out List<byte[]> certificateEntries)
                || certificateEntries.Count == 0)
            {
                throw new DtlsAlertException(
                    DtlsAlert.DecodeError, true, "The server Certificate message was malformed.");
            }

            transcript.AppendMessage(HandshakeType.Certificate, flight[1].Body);
            byte[] transcriptThroughCert = transcript.CurrentHash();

            if (!CertificateVerifyMessage.TryParse(
                    flight[2].Body, out SignatureScheme scheme, out byte[] signature))
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

            transcript.AppendMessage(HandshakeType.CertificateVerify, flight[2].Body);
            byte[] transcriptThroughCv = transcript.CurrentHash();

            if (!Dtls13KeySchedule.VerifyFinished(
                    hash, serverHsSecret, transcriptThroughCv, flight[3].Body))
            {
                throw new DtlsAlertException(
                    DtlsAlert.DecryptError, true, "The server Finished did not verify.");
            }

            transcript.AppendMessage(HandshakeType.Finished, flight[3].Body);

            byte[] transcriptChSf = transcript.CurrentHash();
            await SendClientFinishedAsync(
                    transport,
                    sendHandshake,
                    hash,
                    clientHsSecret,
                    transcriptChSf,
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
            foreach (byte[] secret in secrets)
            {
                CryptographicOperations.ZeroMemory(secret);
            }
        }
    }

    private static async Task<(ServerHello Hello, byte[] Body)> ReceiveServerHelloAsync(
        IDatagramTransport transport,
        CancellationToken cancellationToken)
    {
        byte[] serverHelloDatagram = await ReceiveDatagramAsync(transport, cancellationToken)
            .ConfigureAwait(false);
        if (!Dtls13HandshakeRecords.TryReadPlaintextHandshake(
                serverHelloDatagram, out HandshakeType shType, out byte[] shBody)
            || shType != HandshakeType.ServerHello
            || !ServerHello.TryParse(shBody, out ServerHello serverHello))
        {
            throw new DtlsException("Expected a ServerHello but received a malformed record.");
        }

        if (serverHello.IsHelloRetryRequest)
        {
            throw new DtlsException("HelloRetryRequest is not supported.");
        }

        return (serverHello, shBody);
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
        IDatagramTransport transport,
        Dtls13RecordProtector sendHandshake,
        HashAlgorithmName hash,
        byte[] clientHsSecret,
        byte[] transcriptChSf,
        CancellationToken cancellationToken)
    {
        byte[] clientFinished = Dtls13KeySchedule.ComputeVerifyData(
            hash, clientHsSecret, transcriptChSf);
        byte[] finishedMessage = HandshakeMessage.Serialize(
            HandshakeType.Finished, 1, clientFinished);
        byte[] finishedRecord = Dtls13HandshakeRecords.SealHandshakeRecord(
            sendHandshake, 0, finishedMessage);
        await transport.SendAsync(finishedRecord, cancellationToken).ConfigureAwait(false);
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
                ExtensionType.SignatureAlgorithms,
                SignatureAlgorithmsExtension.Encode(OfferedSignatureSchemes)),
        };

        if (offerRawPublicKey)
        {
            extensions.Add(new HandshakeExtension(
                ExtensionType.ServerCertificateType,
                ServerCertificateTypeExtension.EncodeClientHello(
                    new[] { CertificateType.RawPublicKey, CertificateType.X509 })));
        }

        if (connectionId.Length > 0)
        {
            extensions.Add(new HandshakeExtension(
                ExtensionType.ConnectionId, ConnectionIdExtension.Encode(connectionId)));
        }

        ClientHello clientHello = new()
        {
            Random = random,
            CipherSuites = offeredIds,
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
