using System;
using System.Collections.Generic;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Threading;
using System.Threading.Tasks;
using Dtls.Crypto;
using Dtls.Protocol.V13;
using Dtls.Protocol.V13.Handshake;
using Dtls.Transport;

namespace Dtls.Protocol.V12.Handshake;

/// <summary>
/// The managed DTLS 1.2 client handshake driver (RFC 6347 / RFC 5246) for the certificate-
/// authenticated ECDHE suites (RFC 5289). It sends a ClientHello, performs the HelloVerifyRequest
/// cookie exchange, processes the server flight (ServerHello / Certificate / ServerKeyExchange /
/// optional CertificateRequest / ServerHelloDone), verifies the server's signed ephemeral key,
/// answers with ClientKeyExchange (and, when requested, client Certificate + CertificateVerify),
/// ChangeCipherSpec, and Finished, then verifies the server's Finished. The extended_master_secret
/// extension (RFC 7627) is always offered and required from the peer. Flights are driven through
/// the shared <see cref="Dtls13FlightTransceiver"/> for retransmission on loss.
/// </summary>
internal static class Dtls12ClientHandshake
{
    private static readonly ushort[] OfferedSignatureAlgorithms =
    {
        0x0403, // ecdsa_secp256r1_sha256
        0x0503, // ecdsa_secp384r1_sha384
        0x0603, // ecdsa_secp521r1_sha512
        0x0401, // rsa_pkcs1_sha256
        0x0501, // rsa_pkcs1_sha384
        0x0601, // rsa_pkcs1_sha512
    };

    private static readonly NamedGroup[] OfferedGroups =
    {
        NamedGroup.Secp256r1,
        NamedGroup.Secp384r1,
        NamedGroup.Secp521r1,
    };

    public static async Task<DtlsConnection> RunAsync(
        IDatagramTransport transport,
        DtlsClientOptions options,
        CancellationToken cancellationToken)
    {
        IReadOnlyList<ushort> offeredSuites = Dtls12CipherSuite.DefaultIdsFor(
            certificate: true, ecdhePsk: false, plainPsk: false);

        byte[] clientRandom = new byte[Dtls12ClientHello.RandomLength];
        RandomNumberGenerator.Fill(clientRandom);

        Dtls13FlightTransceiver transceiver = new(
            transport, options.HandshakeRetransmissionTimeout, options.MaxHandshakeRetransmissions);

        // Flight 1: cookieless ClientHello (message_seq 0).
        byte[] helloNoCookie = BuildClientHello(clientRandom, Array.Empty<byte>(), offeredSuites);
        ulong recordSequence = await Dtls12Flight.SendPlaintextFlightAsync(
                transceiver,
                new[] { new OutboundHandshakeMessage(HandshakeType.ClientHello, 0, helloNoCookie) },
                0,
                cancellationToken)
            .ConfigureAwait(false);

        // Flight 2: HelloVerifyRequest with the stateless cookie.
        HandshakeReassembler verifyReassembler =
            new(options.MaxHandshakeMessageSize, firstSequence: 0);
        List<Dtls13HandshakeRecords.Message> verifyFlight =
            await Dtls12Flight.ReceivePlaintextFlightAsync(
                    transceiver,
                    verifyReassembler,
                    HandshakeType.HelloVerifyRequest,
                    cancellationToken)
                .ConfigureAwait(false);
        if (verifyFlight.Count != 1
            || verifyFlight[0].Type != HandshakeType.HelloVerifyRequest
            || !Dtls12HelloVerifyRequest.TryParse(verifyFlight[0].Body, out byte[] cookie))
        {
            throw new DtlsException("Expected a HelloVerifyRequest from the server.");
        }

        // Flight 3: ClientHello with the cookie (message_seq 1) — the transcript starts here.
        byte[] helloWithCookie = BuildClientHello(clientRandom, cookie, offeredSuites);
        var transcript = new PendingTranscript();
        transcript.Defer(HandshakeType.ClientHello, 1, helloWithCookie);
        recordSequence = await Dtls12Flight.SendPlaintextFlightAsync(
                transceiver,
                new[]
                {
                    new OutboundHandshakeMessage(HandshakeType.ClientHello, 1, helloWithCookie),
                },
                recordSequence,
                cancellationToken)
            .ConfigureAwait(false);

        // Flight 4: the server's hello flight, terminated by ServerHelloDone (message_seq 1+).
        HandshakeReassembler serverReassembler =
            new(options.MaxHandshakeMessageSize, firstSequence: 1);
        List<Dtls13HandshakeRecords.Message> serverFlight =
            await Dtls12Flight.ReceivePlaintextFlightAsync(
                    transceiver,
                    serverReassembler,
                    HandshakeType.ServerHelloDone,
                    cancellationToken)
                .ConfigureAwait(false);

        return await CompleteAsync(
                transceiver,
                options,
                clientRandom,
                offeredSuites,
                transcript,
                serverFlight,
                recordSequence,
                cancellationToken)
            .ConfigureAwait(false);
    }

    private static async Task<DtlsConnection> CompleteAsync(
        Dtls13FlightTransceiver transceiver,
        DtlsClientOptions options,
        byte[] clientRandom,
        IReadOnlyList<ushort> offeredSuites,
        PendingTranscript pending,
        IReadOnlyList<Dtls13HandshakeRecords.Message> serverFlight,
        ulong recordSequence,
        CancellationToken cancellationToken)
    {
        ServerFlightParts parts = ParseServerFlight(serverFlight, offeredSuites);

        Dtls12Transcript transcript = new(parts.Suite.PrfHash);
        pending.Flush(transcript);
        foreach (Dtls13HandshakeRecords.Message message in serverFlight)
        {
            transcript.Append(message.Type, message.MessageSequence, message.Body);
        }

        using X509Certificate2 serverCertificate = LoadCertificate(parts.ServerCertificate);
        VerifyServerKeyExchange(serverCertificate, clientRandom, parts);
        ValidateServerCertificate(options, serverCertificate);

        using EcdheKeyExchange ecdhe = EcdheKeyExchange.Create((NamedGroup)parts.NamedCurve);
        byte[] clientPoint = ecdhe.ExportKeyShare();
        byte[] preMasterSecret = ecdhe.DeriveSharedSecret(parts.ServerPoint);

        // Client flight messages (message_seq continues from the cookie ClientHello = 1).
        ushort messageSeq = 2;
        List<OutboundHandshakeMessage> clientMessages = new();

        if (parts.CertificateRequested)
        {
            byte[] certificateBody = BuildClientCertificate(
                options, out X509Certificate2? clientCert);
            clientMessages.Add(new OutboundHandshakeMessage(
                HandshakeType.Certificate, messageSeq, certificateBody));
            transcript.Append(HandshakeType.Certificate, messageSeq, certificateBody);
            messageSeq++;
            pending.SetClientCertificate(clientCert);
        }

        byte[] clientKeyExchange = Dtls12ClientKeyExchange.EncodeEcdhe(clientPoint);
        clientMessages.Add(new OutboundHandshakeMessage(
            HandshakeType.ClientKeyExchange, messageSeq, clientKeyExchange));
        transcript.Append(HandshakeType.ClientKeyExchange, messageSeq, clientKeyExchange);
        messageSeq++;

        if (pending.ClientCertificate is { } signingCert)
        {
            byte[] verifyBody = BuildClientCertificateVerify(
                signingCert, parts.CertificateRequestAlgorithms, transcript);
            clientMessages.Add(new OutboundHandshakeMessage(
                HandshakeType.CertificateVerify, messageSeq, verifyBody));
            transcript.Append(HandshakeType.CertificateVerify, messageSeq, verifyBody);
            messageSeq++;
        }

        // extended_master_secret session_hash = hash of messages through ClientKeyExchange/Verify.
        byte[] sessionHash = transcript.CurrentHash();
        byte[] masterSecret = Dtls12KeySchedule.ExtendedMasterSecret(
            parts.Suite.PrfHash, preMasterSecret, sessionHash);
        CryptographicOperations.ZeroMemory(preMasterSecret);

        Dtls12KeyBlock keyBlock = Dtls12KeySchedule.KeyBlock(
            parts.Suite.PrfHash, masterSecret, parts.ServerRandom, clientRandom,
            parts.Suite.KeyLength);

        Dtls12RecordProtector sendProtector = new(
            parts.Suite, keyBlock.ClientWriteKey, keyBlock.ClientWriteSalt);
        Dtls12RecordProtector receiveProtector = new(
            parts.Suite, keyBlock.ServerWriteKey, keyBlock.ServerWriteSalt);
        keyBlock.Clear();

        DtlsConnection? connection = null;
        try
        {
            byte[] clientVerifyData = Dtls12KeySchedule.VerifyData(
                parts.Suite.PrfHash, masterSecret, transcript.CurrentHash(), clientFinished: true);
            byte[] finishedMessage = HandshakeMessage.Serialize(
                HandshakeType.Finished, messageSeq, clientVerifyData);

            List<byte[]> datagrams = Dtls12Flight.BuildFinalFlight(
                clientMessages,
                recordSequence,
                sendProtector,
                finishedMessage,
                transceiver.Transport.MaxDatagramSize);
            await Dtls12Flight.SendDatagramsAsync(transceiver, datagrams, cancellationToken)
                .ConfigureAwait(false);

            // The server's Finished covers the client Finished too.
            transcript.Append(HandshakeType.Finished, messageSeq, clientVerifyData);

            HandshakeReassembler serverFinalReassembler = new(
                options.MaxHandshakeMessageSize,
                firstSequence: NextServerSequence(serverFlight));
            (_, byte[] serverFinishedBody) = await Dtls12Flight.ReceiveFinalFlightAsync(
                    transceiver, serverFinalReassembler, receiveProtector, cancellationToken)
                .ConfigureAwait(false);

            byte[] expectedServer = Dtls12KeySchedule.VerifyData(
                parts.Suite.PrfHash, masterSecret, transcript.CurrentHash(), clientFinished: false);
            if (!CryptographicOperations.FixedTimeEquals(expectedServer, serverFinishedBody))
            {
                throw new DtlsException("The server Finished verify_data did not match.");
            }

            connection = Dtls12Connection.Create(
                transceiver.Transport, sendProtector, receiveProtector, sendSequenceStart: 1);
            return connection;
        }
        finally
        {
            CryptographicOperations.ZeroMemory(masterSecret);
            if (connection is null)
            {
                sendProtector.Dispose();
                receiveProtector.Dispose();
            }
        }
    }

    private static ushort NextServerSequence(
        IReadOnlyList<Dtls13HandshakeRecords.Message> serverFlight)
    {
        ushort max = 0;
        foreach (Dtls13HandshakeRecords.Message message in serverFlight)
        {
            if (message.MessageSequence > max)
            {
                max = message.MessageSequence;
            }
        }

        return (ushort)(max + 1);
    }

    private static ServerFlightParts ParseServerFlight(
        IReadOnlyList<Dtls13HandshakeRecords.Message> serverFlight,
        IReadOnlyList<ushort> offeredSuites)
    {
        Dtls12ServerHello? serverHello = null;
        List<byte[]>? certificates = null;
        bool certificateRequested = false;
        List<ushort> certificateRequestAlgorithms = new();
        ushort namedCurve = 0;
        byte[] serverPoint = Array.Empty<byte>();
        ushort signatureAlgorithm = 0;
        byte[] signature = Array.Empty<byte>();
        byte[] ecdhParams = Array.Empty<byte>();

        foreach (Dtls13HandshakeRecords.Message message in serverFlight)
        {
            switch (message.Type)
            {
                case HandshakeType.ServerHello:
                    if (!Dtls12ServerHello.TryParse(message.Body, out Dtls12ServerHello hello))
                    {
                        throw new DtlsException("Malformed DTLS 1.2 ServerHello.");
                    }

                    serverHello = hello;
                    break;
                case HandshakeType.Certificate:
                    if (!Dtls12Certificate.TryParse(message.Body, out certificates)
                        || certificates.Count == 0)
                    {
                        throw new DtlsException("Malformed DTLS 1.2 server Certificate.");
                    }

                    break;
                case HandshakeType.ServerKeyExchange:
                    if (!Dtls12ServerKeyExchange.TryParseSigned(
                        message.Body,
                        out namedCurve,
                        out serverPoint,
                        out signatureAlgorithm,
                        out signature,
                        out ecdhParams))
                    {
                        throw new DtlsException("Malformed DTLS 1.2 ServerKeyExchange.");
                    }

                    break;
                case HandshakeType.CertificateRequest:
                    certificateRequested = true;
                    if (!Dtls12CertificateRequest.TryParse(
                        message.Body, out _, out certificateRequestAlgorithms))
                    {
                        certificateRequestAlgorithms = new List<ushort>();
                    }

                    break;
                case HandshakeType.ServerHelloDone:
                    break;
                default:
                    throw new DtlsException(
                        "Unexpected DTLS 1.2 handshake message: " + message.Type + ".");
            }
        }

        if (serverHello is null || certificates is null || serverPoint.Length == 0)
        {
            throw new DtlsException("The server flight was incomplete.");
        }

        if (!Dtls12CipherSuite.TryGet(serverHello.CipherSuite, out Dtls12CipherSuite suite)
            || !Contains(offeredSuites, serverHello.CipherSuite))
        {
            throw new DtlsException("The server selected an unsupported DTLS 1.2 cipher suite.");
        }

        if (!Dtls12Extensions.Has(serverHello.Extensions, ExtensionType.ExtendedMasterSecret))
        {
            throw new DtlsException(
                "The server did not negotiate the extended_master_secret extension.");
        }

        return new ServerFlightParts
        {
            Suite = suite,
            ServerRandom = serverHello.Random,
            ServerCertificate = certificates[0],
            NamedCurve = namedCurve,
            ServerPoint = serverPoint,
            SignatureAlgorithm = signatureAlgorithm,
            Signature = signature,
            EcdhParams = ecdhParams,
            CertificateRequested = certificateRequested,
            CertificateRequestAlgorithms = certificateRequestAlgorithms,
        };
    }

    private static void VerifyServerKeyExchange(
        X509Certificate2 serverCertificate,
        byte[] clientRandom,
        ServerFlightParts parts)
    {
        byte[] signed = new byte[clientRandom.Length + parts.ServerRandom.Length
            + parts.EcdhParams.Length];
        clientRandom.CopyTo(signed, 0);
        parts.ServerRandom.CopyTo(signed, clientRandom.Length);
        parts.EcdhParams.CopyTo(signed, clientRandom.Length + parts.ServerRandom.Length);

        if (!Dtls12Signer.Verify(
            serverCertificate, parts.SignatureAlgorithm, signed, parts.Signature))
        {
            throw new DtlsException("The server ServerKeyExchange signature did not verify.");
        }
    }

    private static byte[] BuildClientCertificate(
        DtlsClientOptions options,
        out X509Certificate2? signingCertificate)
    {
        signingCertificate = null;
        List<byte[]> entries = new();
        if (options.ClientCertificates.Count > 0)
        {
            X509Certificate2 certificate = options.ClientCertificates[0];
            signingCertificate = certificate;
            entries.Add(certificate.RawData);
        }

        return Dtls12Certificate.Encode(entries);
    }

    private static byte[] BuildClientCertificateVerify(
        X509Certificate2 certificate,
        IReadOnlyList<ushort> serverAlgorithms,
        Dtls12Transcript transcript)
    {
        if (!Dtls12Signer.TrySelectAlgorithm(certificate, serverAlgorithms, out ushort algorithm))
        {
            throw new DtlsException(
                "No mutually supported signature algorithm for the client certificate.");
        }

        byte[] content = transcript.CurrentBytes();
        byte[] signature = Dtls12Signer.Sign(certificate, algorithm, content);
        return Dtls12CertificateVerify.Encode(algorithm, signature);
    }

    private static byte[] BuildClientHello(
        byte[] clientRandom,
        byte[] cookie,
        IReadOnlyList<ushort> suites)
    {
        List<HandshakeExtension> extensions = new()
        {
            new HandshakeExtension(
                ExtensionType.SupportedGroups, SupportedGroupsExtension.Encode(OfferedGroups)),
            new HandshakeExtension(
                ExtensionType.EcPointFormats, Dtls12Extensions.EncodeEcPointFormats()),
            new HandshakeExtension(
                ExtensionType.SignatureAlgorithms,
                Dtls12Extensions.EncodeSignatureAlgorithms(OfferedSignatureAlgorithms)),
            new HandshakeExtension(
                ExtensionType.ExtendedMasterSecret,
                Dtls12Extensions.EncodeExtendedMasterSecret()),
        };

        ushort[] suiteArray = new ushort[suites.Count];
        for (int i = 0; i < suites.Count; i++)
        {
            suiteArray[i] = suites[i];
        }

        Dtls12ClientHello hello = new()
        {
            Random = clientRandom,
            Cookie = cookie,
            CipherSuites = suiteArray,
            Extensions = extensions,
        };
        return hello.Encode();
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

    private static bool Contains(IReadOnlyList<ushort> values, ushort value)
    {
        foreach (ushort candidate in values)
        {
            if (candidate == value)
            {
                return true;
            }
        }

        return false;
    }

    private sealed class ServerFlightParts
    {
        public Dtls12CipherSuite Suite { get; init; }

        public byte[] ServerRandom { get; init; } = Array.Empty<byte>();

        public byte[] ServerCertificate { get; init; } = Array.Empty<byte>();

        public ushort NamedCurve { get; init; }

        public byte[] ServerPoint { get; init; } = Array.Empty<byte>();

        public ushort SignatureAlgorithm { get; init; }

        public byte[] Signature { get; init; } = Array.Empty<byte>();

        public byte[] EcdhParams { get; init; } = Array.Empty<byte>();

        public bool CertificateRequested { get; init; }

        public IReadOnlyList<ushort> CertificateRequestAlgorithms { get; init; } =
            Array.Empty<ushort>();
    }

    // Holds the cookie ClientHello until the suite (hence the transcript hash) is known from the
    // ServerHello, plus the chosen client signing certificate for the CertificateVerify path.
    private sealed class PendingTranscript
    {
        private readonly List<(HandshakeType Type, ushort Sequence, byte[] Body)> _deferred = new();

        public X509Certificate2? ClientCertificate { get; private set; }

        public void Defer(HandshakeType type, ushort sequence, byte[] body)
        {
            _deferred.Add((type, sequence, body));
        }

        public void Flush(Dtls12Transcript transcript)
        {
            foreach ((HandshakeType type, ushort sequence, byte[] body) in _deferred)
            {
                transcript.Append(type, sequence, body);
            }
        }

        public void SetClientCertificate(X509Certificate2? certificate)
        {
            ClientCertificate = certificate;
        }
    }
}
