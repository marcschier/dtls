// Copyright (c) marcschier. All rights reserved.
// Licensed under the MIT License. See LICENSE in the project root for license information.

using System;
using Dtls.Internal;
using Xunit;

namespace Dtls.UnitTests;

/// <summary>
/// Boundary and bounds-checking tests for <see cref="SpanReader"/>. Every read must reject
/// truncated input (returning <see langword="false"/> without advancing) and, on success,
/// advance the position by exactly the number of bytes consumed. Multi-byte integers are
/// big-endian. These behaviours are not asserted by the message-parsing tests, which only
/// feed well-formed input.
/// </summary>
public sealed class SpanReaderTests
{
    [Fact]
    public void FreshReader_ReportsPositionAndRemaining()
    {
        byte[] data = { 1, 2, 3 };
        SpanReader reader = new(data);

        Assert.Equal(0, reader.Position);
        Assert.Equal(3, reader.Remaining);
    }

    [Fact]
    public void TryReadByte_ConsumesOneByteAtATime()
    {
        byte[] data = { 0xAB, 0xCD };
        SpanReader reader = new(data);

        Assert.True(reader.TryReadByte(out byte first));
        Assert.Equal(0xAB, first);
        Assert.Equal(1, reader.Position);
        Assert.Equal(1, reader.Remaining);

        Assert.True(reader.TryReadByte(out byte second));
        Assert.Equal(0xCD, second);
        Assert.Equal(0, reader.Remaining);
    }

    [Fact]
    public void TryReadByte_AtEnd_ReturnsFalseAndZero()
    {
        SpanReader reader = new(Array.Empty<byte>());

        Assert.False(reader.TryReadByte(out byte value));
        Assert.Equal(0, value);
        Assert.Equal(0, reader.Position);
    }

    [Fact]
    public void TryReadUInt16_IsBigEndian()
    {
        byte[] data = { 0x12, 0x34 };
        SpanReader reader = new(data);

        Assert.True(reader.TryReadUInt16(out ushort value));
        Assert.Equal(0x1234, value);
        Assert.Equal(2, reader.Position);
    }

    [Fact]
    public void TryReadUInt16_OneByteShort_ReturnsFalseAndDoesNotAdvance()
    {
        byte[] data = { 0x12 };
        SpanReader reader = new(data);

        Assert.False(reader.TryReadUInt16(out ushort value));
        Assert.Equal(0, value);
        Assert.Equal(0, reader.Position);
    }

    [Fact]
    public void TryReadUInt24_IsBigEndian()
    {
        byte[] data = { 0x12, 0x34, 0x56 };
        SpanReader reader = new(data);

        Assert.True(reader.TryReadUInt24(out uint value));
        Assert.Equal(0x123456u, value);
        Assert.Equal(3, reader.Position);
    }

    [Fact]
    public void TryReadUInt24_TwoBytes_ReturnsFalse()
    {
        byte[] data = { 0x12, 0x34 };
        SpanReader reader = new(data);

        Assert.False(reader.TryReadUInt24(out uint value));
        Assert.Equal(0u, value);
    }

    [Fact]
    public void TryReadUInt48_IsBigEndian()
    {
        byte[] data = { 0x01, 0x02, 0x03, 0x04, 0x05, 0x06 };
        SpanReader reader = new(data);

        Assert.True(reader.TryReadUInt48(out ulong value));
        Assert.Equal(0x010203040506ul, value);
        Assert.Equal(6, reader.Position);
    }

    [Fact]
    public void TryReadUInt48_FiveBytes_ReturnsFalse()
    {
        byte[] data = { 0x01, 0x02, 0x03, 0x04, 0x05 };
        SpanReader reader = new(data);

        Assert.False(reader.TryReadUInt48(out ulong value));
        Assert.Equal(0ul, value);
    }

    [Fact]
    public void TryReadBytes_ExactRemaining_Succeeds()
    {
        byte[] data = { 1, 2, 3 };
        SpanReader reader = new(data);

        Assert.True(reader.TryReadBytes(3, out ReadOnlySpan<byte> bytes));
        Assert.Equal(new byte[] { 1, 2, 3 }, bytes.ToArray());
        Assert.Equal(0, reader.Remaining);
    }

    [Fact]
    public void TryReadBytes_OneTooMany_ReturnsFalseAndDoesNotAdvance()
    {
        byte[] data = { 1, 2, 3 };
        SpanReader reader = new(data);

        Assert.False(reader.TryReadBytes(4, out ReadOnlySpan<byte> bytes));
        Assert.True(bytes.IsEmpty);
        Assert.Equal(0, reader.Position);
    }

    [Fact]
    public void TryReadBytes_NegativeCount_ReturnsFalse()
    {
        byte[] data = { 1, 2, 3 };
        SpanReader reader = new(data);

        Assert.False(reader.TryReadBytes(-1, out ReadOnlySpan<byte> bytes));
        Assert.True(bytes.IsEmpty);
        Assert.Equal(0, reader.Position);
    }

    [Fact]
    public void TryReadBytes_ZeroCount_SucceedsWithoutAdvancing()
    {
        byte[] data = { 1, 2, 3 };
        SpanReader reader = new(data);

        Assert.True(reader.TryReadBytes(0, out ReadOnlySpan<byte> bytes));
        Assert.True(bytes.IsEmpty);
        Assert.Equal(0, reader.Position);
    }

    [Fact]
    public void TryReadVector8_RoundTrips()
    {
        byte[] data = { 0x02, 0xAA, 0xBB, 0x99 };
        SpanReader reader = new(data);

        Assert.True(reader.TryReadVector8(out ReadOnlySpan<byte> body));
        Assert.Equal(new byte[] { 0xAA, 0xBB }, body.ToArray());
        Assert.Equal(3, reader.Position);
        Assert.Equal(1, reader.Remaining);
    }

    [Fact]
    public void TryReadVector8_TruncatedBody_ReturnsFalse()
    {
        byte[] data = { 0x05, 0xAA };
        SpanReader reader = new(data);

        Assert.False(reader.TryReadVector8(out ReadOnlySpan<byte> body));
        Assert.True(body.IsEmpty);
    }

    [Fact]
    public void TryReadVector8_MissingLengthPrefix_ReturnsFalse()
    {
        SpanReader reader = new(Array.Empty<byte>());

        Assert.False(reader.TryReadVector8(out _));
    }

    [Fact]
    public void TryReadVector16_RoundTrips()
    {
        byte[] data = { 0x00, 0x03, 0x0A, 0x0B, 0x0C };
        SpanReader reader = new(data);

        Assert.True(reader.TryReadVector16(out ReadOnlySpan<byte> body));
        Assert.Equal(new byte[] { 0x0A, 0x0B, 0x0C }, body.ToArray());
        Assert.Equal(5, reader.Position);
    }

    [Fact]
    public void TryReadVector16_TruncatedBody_ReturnsFalse()
    {
        byte[] data = { 0x00, 0x04, 0x0A, 0x0B };
        SpanReader reader = new(data);

        Assert.False(reader.TryReadVector16(out _));
    }

    [Fact]
    public void TryReadVector24_RoundTrips()
    {
        byte[] data = { 0x00, 0x00, 0x02, 0xEE, 0xFF };
        SpanReader reader = new(data);

        Assert.True(reader.TryReadVector24(out ReadOnlySpan<byte> body));
        Assert.Equal(new byte[] { 0xEE, 0xFF }, body.ToArray());
        Assert.Equal(5, reader.Position);
    }

    [Fact]
    public void TryReadVector24_TruncatedBody_ReturnsFalse()
    {
        byte[] data = { 0x00, 0x00, 0x03, 0xEE };
        SpanReader reader = new(data);

        Assert.False(reader.TryReadVector24(out _));
    }

    [Fact]
    public void TrySkip_AdvancesPosition()
    {
        byte[] data = { 1, 2, 3, 4 };
        SpanReader reader = new(data);

        Assert.True(reader.TrySkip(2));
        Assert.Equal(2, reader.Position);
        Assert.Equal(2, reader.Remaining);
    }

    [Fact]
    public void TrySkip_NegativeCount_ReturnsFalse()
    {
        byte[] data = { 1, 2, 3, 4 };
        SpanReader reader = new(data);

        Assert.False(reader.TrySkip(-1));
        Assert.Equal(0, reader.Position);
    }

    [Fact]
    public void TrySkip_BeyondRemaining_ReturnsFalse()
    {
        byte[] data = { 1, 2 };
        SpanReader reader = new(data);

        Assert.False(reader.TrySkip(3));
        Assert.Equal(0, reader.Position);
    }
}
