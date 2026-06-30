// Copyright (c) marcschier. All rights reserved.
// Licensed under the MIT License. See LICENSE in the project root for license information.

using System;
using Dtls.Internal;
using Xunit;

namespace Dtls.UnitTests;

/// <summary>
/// Tests for <see cref="TlsWriter"/>: big-endian primitives, growable capacity, and the
/// length-prefixed vector backfill (with its overflow guards) used to assemble handshake wire
/// structures. The overflow guards and capacity growth are not exercised by the handshake
/// builders, which only ever write well-formed, in-range structures.
/// </summary>
public sealed class TlsWriterTests
{
    [Fact]
    public void WriteByte_AppendsAndTracksLength()
    {
        TlsWriter writer = new();
        writer.WriteByte(0xAB);

        Assert.Equal(1, writer.Length);
        Assert.Equal(new byte[] { 0xAB }, writer.ToArray());
    }

    [Fact]
    public void WriteUInt16_IsBigEndian()
    {
        TlsWriter writer = new();
        writer.WriteUInt16(0x1234);

        Assert.Equal(new byte[] { 0x12, 0x34 }, writer.ToArray());
    }

    [Fact]
    public void WriteUInt24_IsBigEndian()
    {
        TlsWriter writer = new();
        writer.WriteUInt24(0x123456);

        Assert.Equal(new byte[] { 0x12, 0x34, 0x56 }, writer.ToArray());
    }

    [Fact]
    public void WriteUInt24_Overflow_Throws()
    {
        TlsWriter writer = new();

        Assert.Throws<ArgumentOutOfRangeException>(() => writer.WriteUInt24(0x1000000));
    }

    [Fact]
    public void WriteUInt32_IsBigEndian()
    {
        TlsWriter writer = new();
        writer.WriteUInt32(0x01020304);

        Assert.Equal(new byte[] { 0x01, 0x02, 0x03, 0x04 }, writer.ToArray());
    }

    [Fact]
    public void WriteBytes_Appends()
    {
        TlsWriter writer = new();
        writer.WriteByte(0xFF);
        writer.WriteBytes(new byte[] { 1, 2, 3 });

        Assert.Equal(new byte[] { 0xFF, 1, 2, 3 }, writer.ToArray());
    }

    [Fact]
    public void WrittenSpan_MatchesToArray()
    {
        TlsWriter writer = new();
        writer.WriteBytes(new byte[] { 9, 8, 7 });

        Assert.Equal(writer.ToArray(), writer.WrittenSpan.ToArray());
        Assert.Equal(3, writer.WrittenSpan.Length);
    }

    [Fact]
    public void Vector8_RoundTrips()
    {
        TlsWriter writer = new();
        int start = writer.BeginVector8();
        writer.WriteBytes(new byte[] { 0xAA, 0xBB, 0xCC });
        writer.EndVector8(start);

        Assert.Equal(new byte[] { 0x03, 0xAA, 0xBB, 0xCC }, writer.ToArray());
    }

    [Fact]
    public void Vector8_Empty_WritesZeroLength()
    {
        TlsWriter writer = new();
        int start = writer.BeginVector8();
        writer.EndVector8(start);

        Assert.Equal(new byte[] { 0x00 }, writer.ToArray());
    }

    [Fact]
    public void Vector8_BodyExceeds255_Throws()
    {
        TlsWriter writer = new();
        int start = writer.BeginVector8();
        writer.WriteBytes(new byte[256]);

        Assert.Throws<InvalidOperationException>(() => writer.EndVector8(start));
    }

    [Fact]
    public void Vector16_RoundTrips()
    {
        TlsWriter writer = new();
        int start = writer.BeginVector16();
        writer.WriteBytes(new byte[] { 0x0A, 0x0B, 0x0C });
        writer.EndVector16(start);

        Assert.Equal(new byte[] { 0x00, 0x03, 0x0A, 0x0B, 0x0C }, writer.ToArray());
    }

    [Fact]
    public void Vector24_RoundTrips()
    {
        TlsWriter writer = new();
        int start = writer.BeginVector24();
        writer.WriteBytes(new byte[] { 0xEE, 0xFF });
        writer.EndVector24(start);

        Assert.Equal(new byte[] { 0x00, 0x00, 0x02, 0xEE, 0xFF }, writer.ToArray());
    }

    [Fact]
    public void NestedVectors_BackfillIndependently()
    {
        TlsWriter writer = new();
        int outer = writer.BeginVector16();
        int inner = writer.BeginVector8();
        writer.WriteBytes(new byte[] { 0xAA, 0xBB });
        writer.EndVector8(inner);
        writer.EndVector16(outer);

        // Outer 16-bit length = inner 8-bit prefix (1) + body (2) = 3.
        Assert.Equal(new byte[] { 0x00, 0x03, 0x02, 0xAA, 0xBB }, writer.ToArray());
    }

    [Fact]
    public void EnsureCapacity_GrowsBeyondInitialCapacity()
    {
        TlsWriter writer = new(initialCapacity: 4);
        byte[] payload = new byte[10];
        for (int i = 0; i < payload.Length; i++)
        {
            payload[i] = (byte)(i + 1);
        }

        writer.WriteBytes(payload);

        Assert.Equal(10, writer.Length);
        Assert.Equal(payload, writer.ToArray());
    }

    [Fact]
    public void Constructor_ClampsNonPositiveCapacity()
    {
        TlsWriter writer = new(initialCapacity: 0);
        writer.WriteByte(0x01);

        Assert.Equal(new byte[] { 0x01 }, writer.ToArray());
    }
}
