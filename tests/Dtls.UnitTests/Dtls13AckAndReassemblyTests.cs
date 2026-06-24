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

    [Fact]
    public void Reassembler_WithNonZeroFirstSequence_DeliversThatSequence()
    {
        byte[] body = Enumerable.Range(0, 300).Select(i => (byte)(i % 91)).ToArray();
        List<byte[]> fragments = HandshakeReassembler.Fragment(
            HandshakeType.Certificate, messageSequence: 3, body, maxFragmentBodyLength: 64);

        HandshakeReassembler reassembler = new(maxMessageLength: 64 * 1024, firstSequence: 3);
        OfferAll(reassembler, fragments);

        Assert.True(reassembler.TryReadNext(
            out HandshakeType type, out byte[] reassembled, out ushort seq));
        Assert.Equal(HandshakeType.Certificate, type);
        Assert.Equal(3, seq);
        Assert.Equal(body, reassembled);
    }

    [Fact]
    public void Reassembler_WithNonZeroFirstSequence_DeliversMultiMessageFlightInOrder()
    {
        byte[] eeBody = Enumerable.Range(0, 20).Select(i => (byte)i).ToArray();
        byte[] certBody = Enumerable.Range(0, 400).Select(i => (byte)(i % 83)).ToArray();
        byte[] finBody = Enumerable.Range(0, 32).Select(i => (byte)(i + 1)).ToArray();

        // A mid-handshake flight EE(1), Certificate(2), Finished(3) fragmented to a small MTU.
        List<byte[]> fragments = new();
        fragments.AddRange(HandshakeReassembler.Fragment(
            HandshakeType.EncryptedExtensions, 1, eeBody, 48));
        fragments.AddRange(HandshakeReassembler.Fragment(
            HandshakeType.Certificate, 2, certBody, 48));
        fragments.AddRange(HandshakeReassembler.Fragment(
            HandshakeType.Finished, 3, finBody, 48));

        HandshakeReassembler reassembler = new(maxMessageLength: 64 * 1024, firstSequence: 1);
        OfferAll(reassembler, fragments);

        AssertNext(reassembler, HandshakeType.EncryptedExtensions, 1, eeBody);
        AssertNext(reassembler, HandshakeType.Certificate, 2, certBody);
        AssertNext(reassembler, HandshakeType.Finished, 3, finBody);
        Assert.False(reassembler.TryReadNext(out _, out _, out _));
    }

    [Fact]
    public void Reassembler_WithNonZeroFirstSequence_IgnoresEarlierSequences()
    {
        byte[] earlierBody = Enumerable.Range(0, 10).Select(i => (byte)i).ToArray();
        byte[] flightBody = Enumerable.Range(0, 50).Select(i => (byte)(i % 71)).ToArray();

        List<byte[]> fragments = new();
        // A stray earlier message (seq 0) must be ignored by a flight reassembler starting at 1.
        fragments.AddRange(HandshakeReassembler.Fragment(
            HandshakeType.ServerHello, 0, earlierBody, 64));
        fragments.AddRange(HandshakeReassembler.Fragment(
            HandshakeType.EncryptedExtensions, 1, flightBody, 16));

        HandshakeReassembler reassembler = new(maxMessageLength: 64 * 1024, firstSequence: 1);
        OfferAll(reassembler, fragments);

        AssertNext(reassembler, HandshakeType.EncryptedExtensions, 1, flightBody);
        Assert.False(reassembler.TryReadNext(out _, out _, out _));
    }

    private static void OfferAll(HandshakeReassembler reassembler, List<byte[]> fragments)
    {
        foreach (byte[] fragment in fragments)
        {
            Assert.True(
                HandshakeMessage.TryParseHeader(fragment, out HandshakeMessageHeader header));
            reassembler.Offer(
                header, fragment.AsSpan(HandshakeMessage.HeaderLength, header.FragmentLength));
        }
    }

    private static void AssertNext(
        HandshakeReassembler reassembler,
        HandshakeType expectedType,
        ushort expectedSeq,
        byte[] expectedBody)
    {
        Assert.True(reassembler.TryReadNext(
            out HandshakeType type, out byte[] body, out ushort seq));
        Assert.Equal(expectedType, type);
        Assert.Equal(expectedSeq, seq);
        Assert.Equal(expectedBody, body);
    }

    private static void AssertReassembles(
        List<byte[]> fragments, HandshakeType expectedType, ushort expectedSeq, byte[] expectedBody)
    {
        HandshakeReassembler reassembler = new(maxMessageLength: 64 * 1024, expectedSeq);
        OfferAll(reassembler, fragments);

        Assert.True(reassembler.TryReadNext(
            out HandshakeType type, out byte[] body, out ushort seq));
        Assert.Equal(expectedType, type);
        Assert.Equal(expectedSeq, seq);
        Assert.Equal(expectedBody, body);
        Assert.False(reassembler.TryReadNext(out _, out _, out _));
    }
}
