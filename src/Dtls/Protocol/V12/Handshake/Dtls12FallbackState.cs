using System.Collections.Generic;
using Dtls.Protocol.V13.Handshake;

namespace Dtls.Protocol.V12.Handshake;

/// <summary>
/// The live handshake state handed from the managed DTLS 1.3 client to the managed DTLS 1.2 engine
/// when, after offering both versions, the peer selects DTLS 1.2 (RFC 8446 section 4.2.1 version
/// negotiation). It carries the flight transceiver (which has already sent the offered ClientHello
/// and received the server's first response), the offered ClientHello body and random, and the next
/// epoch-0 record sequence. Exactly one of <see cref="HelloVerifyCookie"/> (the server requested a
/// cookie exchange) or <see cref="ServerFlight"/> (the server replied with its hello flight
/// directly) is set.
/// </summary>
internal sealed class Dtls12FallbackState
{
    public Dtls12FallbackState(
        Dtls13FlightTransceiver transceiver,
        byte[] clientHelloBody,
        byte[] clientRandom,
        ulong recordSequence,
        byte[]? helloVerifyCookie,
        IReadOnlyList<Dtls13HandshakeRecords.Message>? serverFlight)
    {
        Transceiver = transceiver;
        ClientHelloBody = clientHelloBody;
        ClientRandom = clientRandom;
        RecordSequence = recordSequence;
        HelloVerifyCookie = helloVerifyCookie;
        ServerFlight = serverFlight;
    }

    public Dtls13FlightTransceiver Transceiver { get; }

    public byte[] ClientHelloBody { get; }

    public byte[] ClientRandom { get; }

    public ulong RecordSequence { get; }

    public byte[]? HelloVerifyCookie { get; }

    public IReadOnlyList<Dtls13HandshakeRecords.Message>? ServerFlight { get; }
}
