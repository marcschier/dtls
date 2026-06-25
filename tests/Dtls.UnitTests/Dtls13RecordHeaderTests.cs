// Copyright (c) marcschier. All rights reserved.
// Licensed under the MIT License. See LICENSE in the project root for license information.

using System;
using Dtls.Protocol.V13;
using Xunit;

namespace Dtls.UnitTests;

/// <summary>
/// Encode/parse round-trips for the DTLS 1.3 unified record header (RFC 9147 section 4.1).
/// </summary>
public sealed class Dtls13RecordHeaderTests
{
    private static byte[] BuildRecord(
        int epoch,
        byte[] connectionId,
        ushort sequenceNumber,
        bool sixteenBit,
        bool lengthPresent,
        int payloadLength)
    {
        int headerLength = Dtls13RecordHeader.ComputeLength(
            connectionId.Length,
            sixteenBit,
            lengthPresent);
        byte[] buffer = new byte[headerLength + payloadLength];

        int written = Dtls13RecordHeader.Write(
            buffer,
            epoch,
            connectionId,
            sequenceNumber,
            sixteenBit,
            lengthPresent,
            (ushort)payloadLength);

        Assert.Equal(headerLength, written);

        for (int i = 0; i < payloadLength; i++)
        {
            buffer[headerLength + i] = (byte)(0xA0 + i);
        }

        return buffer;
    }

    [Theory]
    [InlineData(false, false)]
    [InlineData(true, false)]
    [InlineData(false, true)]
    [InlineData(true, true)]
    public void RoundTrip_NoConnectionId(bool sixteenBit, bool lengthPresent)
    {
        ushort seq = sixteenBit ? (ushort)0x1234 : (ushort)0x42;
        byte[] record = BuildRecord(2, Array.Empty<byte>(), seq, sixteenBit, lengthPresent, 24);

        bool parsed = Dtls13RecordHeader.TryParse(record, 0, out var info);

        Assert.True(parsed);
        Assert.False(info.ConnectionIdPresent);
        Assert.Equal(sixteenBit, info.SixteenBitSequenceNumber);
        Assert.Equal(lengthPresent, info.LengthPresent);
        Assert.Equal(2, info.EpochLowBits);
        Assert.Equal(seq, info.EncodedSequenceNumber);
        Assert.Equal(24, info.EncryptedRecordLength);
        Assert.Equal(info.HeaderLength, info.EncryptedRecordOffset);
    }

    [Theory]
    [InlineData(false, false)]
    [InlineData(true, false)]
    [InlineData(false, true)]
    [InlineData(true, true)]
    public void RoundTrip_WithConnectionId(bool sixteenBit, bool lengthPresent)
    {
        byte[] cid = { 0xDE, 0xAD, 0xBE, 0xEF };
        ushort seq = sixteenBit ? (ushort)0xABCD : (ushort)0x07;
        byte[] record = BuildRecord(1, cid, seq, sixteenBit, lengthPresent, 32);

        bool parsed = Dtls13RecordHeader.TryParse(record, cid.Length, out var info);

        Assert.True(parsed);
        Assert.True(info.ConnectionIdPresent);
        Assert.Equal(cid.Length, info.ConnectionIdLength);
        Assert.Equal(1, info.ConnectionIdOffset);
        Assert.Equal(cid, record[1..(1 + cid.Length)]);
        Assert.Equal(seq, info.EncodedSequenceNumber);
        Assert.Equal(32, info.EncryptedRecordLength);
    }

    [Fact]
    public void TryParse_RejectsBadFixedBits()
    {
        byte[] record = new byte[8];
        record[0] = 0x80; // top bits not 001

        Assert.False(Dtls13RecordHeader.TryParse(record, 0, out _));
    }

    [Fact]
    public void TryParse_RejectsTruncatedSequenceNumber()
    {
        // 16-bit sequence flag set but only the first byte present.
        byte[] record = { Dtls13RecordHeader.FixedBits | Dtls13RecordHeader.SequenceNumber16Flag };

        Assert.False(Dtls13RecordHeader.TryParse(record, 0, out _));
    }

    [Fact]
    public void TryParse_RejectsLengthBeyondBuffer()
    {
        byte[] record = new byte[Dtls13RecordHeader.ComputeLength(0, false, true)];
        Dtls13RecordHeader.Write(record, 0, Array.Empty<byte>(), 1, false, true, 100);

        // Declared length 100 but the buffer carries no payload.
        Assert.False(Dtls13RecordHeader.TryParse(record, 0, out _));
    }
}
