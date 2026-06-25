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
/// The managed DTLS 1.2 server handshake driver (RFC 6347 / RFC 5246) for the certificate-
/// authenticated ECDHE suites (RFC 5289). It performs a stateless HelloVerifyRequest cookie
/// exchange, sends its hello flight (ServerHello / Certificate / signed ServerKeyExchange /
/// optional CertificateRequest / ServerHelloDone), receives the client's ClientKeyExchange (and
/// optional Certificate / CertificateVerify), ChangeCipherSpec and Finished, then replies with its
/// own ChangeCipherSpec and Finished. The extended_master_secret extension (RFC 7627) is required.
/// </summary>
internal static class Dtls12ServerHandshake
{
    private static readonly byte[] CookieSecret = CreateCookieSecret();

    public static async Task<DtlsConnection> RunAsync(
        IDatagramTransport transport,
        DtlsServerOptions options,
        ReadOnlyMemory<byte> initialDatagram,
        CancellationToken cancellationToken)
    {
        if (options.ServerCertificate is null)
        {
            throw new DtlsException(
                "The managed DTLS 1.2 server requires a ServerCertificate.");
        }

        if (!Dtls13HandshakeRecords.TryReadPlaintextHandshake(
                initialDatagram.Span, out HandshakeType type, out byte[] helloBody)
            || type != HandshakeType.ClientHello
            || !Dtls12ClientHello.TryParse(helloBody, out Dtls12ClientHello clientHello))
        {
            throw new DtlsException("The initial datagram was not a valid DTLS 1.2 ClientHello.");
        }

        Dtls13FlightTransceiver transceiver = new(
            transport, options.HandshakeRetransmissionTimeout, options.MaxHandshakeRetransmissions);
        transceiver.Seed(initialDatagram.Span);

        // Flight: HelloVerifyRequest with the stateless cookie (message_seq 0).
        byte[] cookie = Dtls12Cookie.Build(CookieSecret, clientHello.Random);
        byte[] verifyBody = Dtls12HelloVerifyRequest.Encode(cookie);
        ulong recordSequence = await Dtls12Flight.SendPlaintextFlightAsync(
                transceiver,
                new[]
                {
                    new OutboundHandshakeMessage(HandshakeType.HelloVerifyRequest, 0, verifyBody),
                },
                0,
                cancellationToken)
            .ConfigureAwait(false);

        // Receive the second ClientHello (message_seq 1) carrying the cookie.
        HandshakeReassembler helloReassembler =
            new(options.MaxHandshakeMessageSize, firstSequence: 1);
        List<Dtls13HandshakeRecords.Message> helloFlight =
            await Dtls12Flight.ReceivePlaintextFlightAsync(
                    transceiver, helloReassembler, HandshakeType.ClientHello, cancellationToken)
                .ConfigureAwait(false);
        if (helloFlight.Count != 1
            || !Dtls12ClientHello.TryParse(helloFlight[0].Body, out clientHello))
        {
            throw new DtlsException("Expected a cookie ClientHello from the client.");
        }

        if (!Dtls12Cookie.Verify(CookieSecret, clientHello.Random, clientHello.Cookie))
        {
            throw new DtlsException("The ClientHello cookie did not verify.");
        }

        return await CompleteAsync(
                transceiver,
                options,
                clientHello,
                helloFlight[0].Body,
                recordSequence,
                cancellationToken)
            .ConfigureAwait(false);
    }

    private static async Task<DtlsConnection> CompleteAsync(
        Dtls13FlightTransceiver transceiver,
        DtlsServerOptions options,
        Dtls12ClientHello clientHello,
        byte[] clientHelloBody,
        ulong recordSequence,
        CancellationToken cancellationToken)
    {
        X509Certificate2 serverCertificate = options.ServerCertificate!;
        Dtls12CipherSuite suite = SelectCipherSuite(clientHello, serverCertificate);
        NamedGroup group = SelectGroup(clientHello);

        if (!Dtls12Extensions.Has(clientHello.Extensions, ExtensionType.ExtendedMasterSecret))
        {
            throw new DtlsException(
                "The client did not offer the extended_master_secret extension.");
        }

        byte[] serverRandom = new byte[Dtls12ClientHello.RandomLength];
        RandomNumberGenerator.Fill(serverRandom);

        Dtls12Transcript transcript = new(suite.PrfHash);
        transcript.Append(HandshakeType.ClientHello, 1, clientHelloBody);

        using EcdheKeyExchange ecdhe = EcdheKeyExchange.Create(group);
        byte[] serverPoint = ecdhe.ExportKeyShare();
        byte[] ecdhParams = Dtls12ServerKeyExchange.EncodeEcdhParams((ushort)group, serverPoint);

        IReadOnlyList<ushort> clientAlgorithms = ParseClientSignatureAlgorithms(clientHello);
        if (!Dtls12Signer.TrySelectAlgorithm(
            serverCertificate, clientAlgorithms, out ushort signatureAlgorithm))
        {
            throw new DtlsException(
                "No mutually supported signature algorithm for the server certificate.");
        }

        byte[] signedContent = Concat(clientHello.Random, serverRandom, ecdhParams);
        byte[] signature = Dtls12Signer.Sign(serverCertificate, signatureAlgorithm, signedContent);
        CryptographicOperations.ZeroMemory(signedContent);

        // Server hello flight (message_seq 1..N).
        List<OutboundHandshakeMessage> flight = new();
        ushort seq = 1;

        byte[] serverHelloBody = BuildServerHello(serverRandom, suite.Id);
        flight.Add(new OutboundHandshakeMessage(HandshakeType.ServerHello, seq, serverHelloBody));
        transcript.Append(HandshakeType.ServerHello, seq, serverHelloBody);
        seq++;

        byte[] certificateBody = Dtls12Certificate.Encode(new[] { serverCertificate.RawData });
        flight.Add(new OutboundHandshakeMessage(HandshakeType.Certificate, seq, certificateBody));
        transcript.Append(HandshakeType.Certificate, seq, certificateBody);
        seq++;

        byte[] serverKeyExchange = Dtls12ServerKeyExchange.EncodeSigned(
            ecdhParams, signatureAlgorithm, signature);
        flight.Add(new OutboundHandshakeMessage(
            HandshakeType.ServerKeyExchange, seq, serverKeyExchange));
        transcript.Append(HandshakeType.ServerKeyExchange, seq, serverKeyExchange);
        seq++;

        bool requestClientCertificate = options.RequireClientCertificate;
        if (requestClientCertificate)
        {
            byte[] requestBody = Dtls12CertificateRequest.Encode(
                new byte[] { Dtls12CertificateRequest.EcdsaSign, Dtls12CertificateRequest.RsaSign },
                new ushort[] { 0x0403, 0x0503, 0x0401, 0x0501 });
            flight.Add(new OutboundHandshakeMessage(
                HandshakeType.CertificateRequest, seq, requestBody));
            transcript.Append(HandshakeType.CertificateRequest, seq, requestBody);
            seq++;
        }

        byte[] doneBody = Array.Empty<byte>();
        flight.Add(new OutboundHandshakeMessage(HandshakeType.ServerHelloDone, seq, doneBody));
        transcript.Append(HandshakeType.ServerHelloDone, seq, doneBody);
        ushort serverFinishedSeq = (ushort)(seq + 1);

        recordSequence = await Dtls12Flight.SendPlaintextFlightAsync(
                transceiver, flight, recordSequence, cancellationToken)
            .ConfigureAwait(false);

        return await ReceiveClientFinishAndCompleteAsync(
                transceiver,
                options,
                suite,
                ecdhe,
                clientHello.Random,
                serverRandom,
                transcript,
                requestClientCertificate,
                serverFinishedSeq,
                recordSequence,
                cancellationToken)
            .ConfigureAwait(false);
    }

    private static async Task<DtlsConnection> ReceiveClientFinishAndCompleteAsync(
        Dtls13FlightTransceiver transceiver,
        DtlsServerOptions options,
        Dtls12CipherSuite suite,
        EcdheKeyExchange ecdhe,
        byte[] clientRandom,
        byte[] serverRandom,
        Dtls12Transcript transcript,
        bool requestedClientCertificate,
        ushort serverFinishedSeq,
        ulong recordSequence,
        CancellationToken cancellationToken)
    {
        HandshakeReassembler reassembler =
            new(options.MaxHandshakeMessageSize, firstSequence: 2);
        List<byte[]> bufferedProtected = new();

        byte[]? masterSecret = null;
        Dtls12RecordProtector? sendProtector = null;
        Dtls12RecordProtector? receiveProtector = null;
        bool clientCertificateRequired = options.RequireClientCertificate;
        X509Certificate2? clientCertificate = null;
        ushort pendingCertVerifyAlgorithm = 0;
        byte[]? pendingCertVerifySignature = null;
        byte[]? pendingCertVerifyContent = null;
        byte[]? clientFinishedBody = null;

        try
        {
            while (clientFinishedBody is null)
            {
                byte[] datagram = await transceiver.ReceiveFlightAsync(cancellationToken)
                    .ConfigureAwait(false);

                ReadOnlySpan<byte> remaining = datagram;
                while (Dtls13PlaintextRecord.TryParse(
                    remaining,
                    out byte contentType,
                    out ushort epoch,
                    out _,
                    out ReadOnlySpan<byte> fragment,
                    out int consumed))
                {
                    ReadOnlySpan<byte> record = remaining.Slice(0, consumed);
                    remaining = remaining.Slice(consumed);

                    if (epoch == 0
                        && contentType == Dtls13PlaintextRecord.HandshakeContentType)
                    {
                        Dtls13HandshakeFlight.OfferFragment(fragment, reassembler);
                    }
                    else if (epoch >= 1
                        && contentType == Dtls13PlaintextRecord.HandshakeContentType)
                    {
                        bufferedProtected.Add(record.ToArray());
                    }
                }

                while (reassembler.TryReadNext(
                    out HandshakeType type, out byte[] body, out ushort sequence))
                {
                    ProcessClientPlaintextMessage(
                        type,
                        body,
                        sequence,
                        transcript,
                        ref clientCertificate,
                        ref pendingCertVerifyAlgorithm,
                        ref pendingCertVerifySignature,
                        ref pendingCertVerifyContent);

                    if (type == HandshakeType.ClientKeyExchange)
                    {
                        DeriveKeys(
                            suite,
                            ecdhe,
                            body,
                            clientRandom,
                            serverRandom,
                            transcript,
                            ref masterSecret,
                            ref sendProtector,
                            ref receiveProtector);
                    }
                }

                if (receiveProtector is not null)
                {
                    clientFinishedBody = TryOpenFinished(bufferedProtected, receiveProtector);
                }
            }

            VerifyClientAuthentication(
                clientCertificateRequired,
                clientCertificate,
                pendingCertVerifyAlgorithm,
                pendingCertVerifySignature,
                pendingCertVerifyContent,
                options);

            byte[] expectedClient = Dtls12KeySchedule.VerifyData(
                suite.PrfHash, masterSecret!, ClientFinishTranscriptHash(transcript),
                clientFinished: true);
            if (!CryptographicOperations.FixedTimeEquals(expectedClient, clientFinishedBody))
            {
                throw new DtlsException("The client Finished verify_data did not match.");
            }

            // Append the client Finished so the server Finished covers it.
            transcript.Append(
                HandshakeType.Finished, ClientFinishedSeq(reassembler), clientFinishedBody);

            byte[] serverVerifyData = Dtls12KeySchedule.VerifyData(
                suite.PrfHash, masterSecret!, transcript.CurrentHash(), clientFinished: false);
            byte[] serverFinished = HandshakeMessage.Serialize(
                HandshakeType.Finished, serverFinishedSeq, serverVerifyData);

            List<byte[]> datagrams = Dtls12Flight.BuildFinalFlight(
                Array.Empty<OutboundHandshakeMessage>(),
                recordSequence,
                sendProtector!,
                serverFinished,
                transceiver.Transport.MaxDatagramSize);
            await Dtls12Flight.SendDatagramsAsync(transceiver, datagrams, cancellationToken)
                .ConfigureAwait(false);

            DtlsConnection connection = Dtls12Connection.Create(
                transceiver.Transport, sendProtector!, receiveProtector!, sendSequenceStart: 1);
            sendProtector = null;
            receiveProtector = null;
            return connection;
        }
        finally
        {
            clientCertificate?.Dispose();
            if (masterSecret is not null)
            {
                CryptographicOperations.ZeroMemory(masterSecret);
            }

            sendProtector?.Dispose();
            receiveProtector?.Dispose();
        }
    }

    private static void ProcessClientPlaintextMessage(
        HandshakeType type,
        byte[] body,
        ushort sequence,
        Dtls12Transcript transcript,
        ref X509Certificate2? clientCertificate,
        ref ushort certVerifyAlgorithm,
        ref byte[]? certVerifySignature,
        ref byte[]? certVerifyContent)
    {
        // The CertificateVerify signs the transcript through ClientKeyExchange (it excludes the
        // CertificateVerify message itself), so capture that snapshot before appending it.
        if (type == HandshakeType.CertificateVerify)
        {
            certVerifyContent = transcript.CurrentBytes();
        }

        transcript.Append(type, sequence, body);
        switch (type)
        {
            case HandshakeType.Certificate:
                if (Dtls12Certificate.TryParse(body, out List<byte[]> certificates)
                    && certificates.Count > 0)
                {
                    clientCertificate = LoadCertificate(certificates[0]);
                }

                break;
            case HandshakeType.CertificateVerify:
                if (Dtls12CertificateVerify.TryParse(
                    body, out certVerifyAlgorithm, out byte[] signature))
                {
                    certVerifySignature = signature;
                }

                break;
            case HandshakeType.ClientKeyExchange:
                break;
            default:
                throw new DtlsException(
                    "Unexpected DTLS 1.2 client message: " + type + ".");
        }
    }

    private static void DeriveKeys(
        Dtls12CipherSuite suite,
        EcdheKeyExchange ecdhe,
        byte[] clientKeyExchangeBody,
        byte[] clientRandom,
        byte[] serverRandom,
        Dtls12Transcript transcript,
        ref byte[]? masterSecret,
        ref Dtls12RecordProtector? sendProtector,
        ref Dtls12RecordProtector? receiveProtector)
    {
        if (!Dtls12ClientKeyExchange.TryParseEcdhe(clientKeyExchangeBody, out byte[] clientPoint))
        {
            throw new DtlsException("Malformed DTLS 1.2 ClientKeyExchange.");
        }

        byte[] preMasterSecret = ecdhe.DeriveSharedSecret(clientPoint);

        // The extended_master_secret session_hash spans messages through ClientKeyExchange.
        byte[] sessionHash = transcript.CurrentHash();
        masterSecret = Dtls12KeySchedule.ExtendedMasterSecret(
            suite.PrfHash, preMasterSecret, sessionHash);
        CryptographicOperations.ZeroMemory(preMasterSecret);

        Dtls12KeyBlock keyBlock = Dtls12KeySchedule.KeyBlock(
            suite.PrfHash, masterSecret, serverRandom, clientRandom, suite.KeyLength);
        sendProtector = new Dtls12RecordProtector(
            suite, keyBlock.ServerWriteKey, keyBlock.ServerWriteSalt);
        receiveProtector = new Dtls12RecordProtector(
            suite, keyBlock.ClientWriteKey, keyBlock.ClientWriteSalt);
        keyBlock.Clear();
    }

    private static byte[]? TryOpenFinished(
        List<byte[]> bufferedProtected,
        Dtls12RecordProtector receiveProtector)
    {
        foreach (byte[] record in bufferedProtected)
        {
            if (receiveProtector.TryOpen(
                    record, out byte contentType, out byte[] opened, out _, out _, out _)
                && contentType == Dtls13PlaintextRecord.HandshakeContentType
                && HandshakeMessage.TryParse(
                    opened, out HandshakeMessageHeader header, out ReadOnlySpan<byte> body)
                && header.MessageType == HandshakeType.Finished)
            {
                return body.ToArray();
            }
        }

        return null;
    }

    // The client Finished verify_data hashes the transcript up to (but not including) the Finished;
    // that is the transcript state right after the last client plaintext message.
    private static byte[] ClientFinishTranscriptHash(Dtls12Transcript transcript)
    {
        return transcript.CurrentHash();
    }

    private static ushort ClientFinishedSeq(HandshakeReassembler reassembler)
    {
        return reassembler.NextExpectedSequence;
    }

    private static void VerifyClientAuthentication(
        bool required,
        X509Certificate2? clientCertificate,
        ushort certVerifyAlgorithm,
        byte[]? certVerifySignature,
        byte[]? certVerifyContent,
        DtlsServerOptions options)
    {
        if (clientCertificate is null)
        {
            if (required)
            {
                throw new DtlsAlertException(
                    DtlsAlert.HandshakeFailure,
                    true,
                    "A client certificate was required but not provided.");
            }

            return;
        }

        if (certVerifySignature is null || certVerifyContent is null)
        {
            throw new DtlsException(
                "The client Certificate was not followed by a CertificateVerify.");
        }

        if (!Dtls12Signer.Verify(
            clientCertificate, certVerifyAlgorithm, certVerifyContent, certVerifySignature))
        {
            throw new DtlsException("The client CertificateVerify did not verify.");
        }

        if (options.ClientCertificateValidation is not null)
        {
            using X509Chain chain = new();
            chain.ChainPolicy.RevocationMode = X509RevocationMode.NoCheck;
            chain.Build(clientCertificate);
            if (!options.ClientCertificateValidation(clientCertificate, chain, false))
            {
                throw new DtlsAlertException(
                    DtlsAlert.BadCertificate,
                    true,
                    "The client certificate was rejected by ClientCertificateValidation.");
            }
        }
    }

    private static IReadOnlyList<ushort> ParseClientSignatureAlgorithms(
        Dtls12ClientHello clientHello)
    {
        if (ExtensionList.TryFind(
                clientHello.Extensions,
                ExtensionType.SignatureAlgorithms,
                out HandshakeExtension ext)
            && Dtls12Extensions.TryParseSignatureAlgorithms(ext.Data, out List<ushort> algorithms))
        {
            return algorithms;
        }

        return Array.Empty<ushort>();
    }

    private static Dtls12CipherSuite SelectCipherSuite(
        Dtls12ClientHello clientHello,
        X509Certificate2 serverCertificate)
    {
        bool isEcdsa;
        using (ECDsa? ecdsa = serverCertificate.GetECDsaPublicKey())
        {
            isEcdsa = ecdsa is not null;
        }

        foreach (ushort id in clientHello.CipherSuites)
        {
            if (!Dtls12CipherSuite.TryGet(id, out Dtls12CipherSuite suite)
                || !suite.UsesCertificate)
            {
                continue;
            }

            bool suiteEcdsa = suite.KeyExchange == Dtls12KeyExchange.EcdheEcdsa;
            if (suiteEcdsa == isEcdsa)
            {
                return suite;
            }
        }

        throw new DtlsException(
            "No mutually supported certificate cipher suite for the server certificate.");
    }

    private static NamedGroup SelectGroup(Dtls12ClientHello clientHello)
    {
        if (ExtensionList.TryFind(
                clientHello.Extensions, ExtensionType.SupportedGroups, out HandshakeExtension ext)
            && SupportedGroupsExtension.TryParse(ext.Data, out List<NamedGroup> groups))
        {
            foreach (NamedGroup group in groups)
            {
                if (EcdheKeyExchange.IsSupported(group))
                {
                    return group;
                }
            }
        }

        throw new DtlsException("No mutually supported named group for ECDHE.");
    }

    private static byte[] BuildServerHello(byte[] serverRandom, ushort cipherSuite)
    {
        List<HandshakeExtension> extensions = new()
        {
            new HandshakeExtension(
                ExtensionType.ExtendedMasterSecret,
                Dtls12Extensions.EncodeExtendedMasterSecret()),
            new HandshakeExtension(
                ExtensionType.EcPointFormats, Dtls12Extensions.EncodeEcPointFormats()),
        };

        Dtls12ServerHello hello = new()
        {
            Random = serverRandom,
            CipherSuite = cipherSuite,
            Extensions = extensions,
        };
        return hello.Encode();
    }

    private static byte[] Concat(byte[] a, byte[] b, byte[] c)
    {
        byte[] result = new byte[a.Length + b.Length + c.Length];
        a.CopyTo(result, 0);
        b.CopyTo(result, a.Length);
        c.CopyTo(result, a.Length + b.Length);
        return result;
    }

    private static X509Certificate2 LoadCertificate(byte[] der)
    {
#if NET9_0_OR_GREATER
        return X509CertificateLoader.LoadCertificate(der);
#else
        return new X509Certificate2(der);
#endif
    }

    private static byte[] CreateCookieSecret()
    {
        byte[] secret = new byte[32];
        RandomNumberGenerator.Fill(secret);
        return secret;
    }
}
