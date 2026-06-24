using System;
using System.Collections.Generic;
using System.Linq;
using Dtls.Protocol.V13;
using Dtls.Protocol.V13.Handshake;
using Xunit;

namespace Dtls.UnitTests;

/// <summary>
/// Unit tests for the DTLS 1.3 ACK record codec (RFC 9147 section 7) and the handshake
/// fragmentation/reassembly helper (RFC 9147 section 5.5).
/// </summary>
public sealed class Dtls13AckAndReassemblyTests
{
    [Fact]
    public void Ack_RoundTrips_RecordNumbers()
    {
        List<RecordNumber> numbers = new()
        {
            new RecordNumber(0, 0),
            new RecordNumber(2, 1),
            new RecordNumber(3, 0x0000FFFFFFFFFFFF),
        };

        byte[] body = Dtls13Ack.Encode(numbers);

        Assert.True(Dtls13Ack.TryParse(body, out List<RecordNumber> parsed));
        Assert.Equal(numbers, parsed);
    }

    [Fact]
    public void Ack_Empty_RoundTrips()
    {
        byte[] body = Dtls13Ack.Encode(new List<RecordNumber>());

        Assert.True(Dtls13Ack.TryParse(body, out List<RecordNumber> parsed));
        Assert.Empty(parsed);
    }

    [Fact]
    public void Ack_Malformed_LengthNotMultiple_Fails()
    {
        // Declares 8 bytes of record numbers (not a multiple of 16).
        byte[] body = { 0x00, 0x08, 1, 2, 3, 4, 5, 6, 7, 8 };

        Assert.False(Dtls13Ack.TryParse(body, out _));
    }

    [Fact]
    public void Reassembler_SingleFragment_WhenMessageFits()
    {
        byte[] originalBody = Enumerable.Range(0, 40).Select(i => (byte)i).ToArray();

        List<byte[]> fragments = HandshakeReassembler.Fragment(
            HandshakeType.EncryptedExtensions, 0, originalBody, maxFragmentBodyLength: 256);

        Assert.Single(fragments);
        AssertReassembles(fragments, HandshakeType.EncryptedExtensions, 0, originalBody);
    }

    [Fact]
    public void Reassembler_Reassembles_InOrderFragments()
    {
        byte[] originalBody = Enumerable.Range(0, 1000).Select(i => (byte)(i % 251)).ToArray();

        List<byte[]> fragments = HandshakeReassembler.Fragment(
            HandshakeType.Certificate, 0, originalBody, maxFragmentBodyLength: 100);

        Assert.True(fragments.Count >= 10);
        AssertReassembles(fragments, HandshakeType.Certificate, 0, originalBody);
    }

    [Fact]
    public void Reassembler_Reassembles_OutOfOrderAndDuplicateFragments()
    {
        byte[] originalBody = Enumerable.Range(0, 500).Select(i => (byte)(i % 97)).ToArray();

        List<byte[]> fragments = HandshakeReassembler.Fragment(
            HandshakeType.Certificate, 0, originalBody, maxFragmentBodyLength: 64);

        // Reverse order plus a duplicate of the first fragment.
        List<byte[]> shuffled = fragments.AsEnumerable().Reverse().ToList();
        shuffled.Add(fragments[0]);

        AssertReassembles(shuffled, HandshakeType.Certificate, 0, originalBody);
    }

    private static void AssertReassembles(
        List<byte[]> fragments, HandshakeType expectedType, ushort expectedSeq, byte[] expectedBody)
    {
        HandshakeReassembler reassembler = new(maxMessageLength: 64 * 1024);
        foreach (byte[] fragment in fragments)
        {
            Assert.True(
                HandshakeMessage.TryParseHeader(fragment, out HandshakeMessageHeader header));
            reassembler.Offer(
                header, fragment.AsSpan(HandshakeMessage.HeaderLength, header.FragmentLength));
        }

        Assert.True(reassembler.TryReadNext(
            out HandshakeType type, out byte[] body, out ushort seq));
        Assert.Equal(expectedType, type);
        Assert.Equal(expectedSeq, seq);
        Assert.Equal(expectedBody, body);
        Assert.False(reassembler.TryReadNext(out _, out _, out _));
    }
}
