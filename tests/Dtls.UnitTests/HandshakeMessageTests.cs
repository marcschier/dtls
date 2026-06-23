using System;
using Dtls.Internal;
using Dtls.Protocol.V13.Handshake;
using Xunit;

namespace Dtls.UnitTests;

/// <summary>
/// Encode/parse round-trips for the DTLS 1.3 handshake message header and full message
/// (RFC 9147 section 5.2), and the TLS 1.3 reconstructed transcript bytes.
/// </summary>
public sealed class HandshakeMessageTests
{
    [Fact]
    public void Header_RoundTrips_WithSequenceAndFragmentFields()
    {
        TlsWriter writer = new();
        HandshakeMessage.WriteHeader(
            writer,
            HandshakeType.ClientHello,
            length: 0x010203,
            messageSequence: 0x1122,
            fragmentOffset: 0x040506,
            fragmentLength: 0x070809);

        byte[] bytes = writer.ToArray();
        Assert.Equal(HandshakeMessage.HeaderLength, bytes.Length);

        Assert.True(HandshakeMessage.TryParseHeader(bytes, out HandshakeMessageHeader header));
        Assert.Equal(HandshakeType.ClientHello, header.MessageType);
        Assert.Equal(0x010203, header.Length);
        Assert.Equal(0x1122, header.MessageSequence);
        Assert.Equal(0x040506, header.FragmentOffset);
        Assert.Equal(0x070809, header.FragmentLength);
    }

    [Fact]
    public void Serialize_FullMessage_RoundTrips()
    {
        byte[] body = { 1, 2, 3, 4, 5 };
        byte[] message = HandshakeMessage.Serialize(HandshakeType.Finished, 7, body);

        Assert.True(HandshakeMessage.TryParse(
            message,
            out HandshakeMessageHeader header,
            out ReadOnlySpan<byte> parsedBody));
        Assert.Equal(HandshakeType.Finished, header.MessageType);
        Assert.Equal(7, header.MessageSequence);
        Assert.Equal(body.Length, header.Length);
        Assert.Equal(0, header.FragmentOffset);
        Assert.Equal(body.Length, header.FragmentLength);
        Assert.Equal(body, parsedBody.ToArray());
    }

    [Fact]
    public void TryParseHeader_Truncated_Fails()
    {
        byte[] tooShort = new byte[HandshakeMessage.HeaderLength - 1];
        Assert.False(HandshakeMessage.TryParseHeader(tooShort, out _));
    }

    [Fact]
    public void TryParse_FragmentedMessage_Fails()
    {
        TlsWriter writer = new();
        HandshakeMessage.WriteHeader(writer, HandshakeType.ClientHello, 100, 0, 10, 20);
        writer.WriteBytes(new byte[20]);

        Assert.False(HandshakeMessage.TryParse(writer.ToArray(), out _, out _));
    }

    [Fact]
    public void TryParse_BodyShorterThanLength_Fails()
    {
        byte[] message = HandshakeMessage.Serialize(HandshakeType.Finished, 0, new byte[10]);
        byte[] truncated = message.AsSpan(0, message.Length - 1).ToArray();
        Assert.False(HandshakeMessage.TryParse(truncated, out _, out _));
    }

    [Fact]
    public void ToTranscriptBytes_OmitsDtlsFragmentFields()
    {
        byte[] body = { 0xAA, 0xBB };
        byte[] transcript = HandshakeMessage.ToTranscriptBytes(HandshakeType.ServerHello, body);

        Assert.Equal(4 + body.Length, transcript.Length);
        Assert.Equal((byte)HandshakeType.ServerHello, transcript[0]);
        Assert.Equal(0x00, transcript[1]);
        Assert.Equal(0x00, transcript[2]);
        Assert.Equal(0x02, transcript[3]);
        Assert.Equal(body, transcript.AsSpan(4).ToArray());
    }
}
