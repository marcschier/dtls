// Copyright (c) marcschier. All rights reserved.
// Licensed under the MIT License. See LICENSE in the project root for license information.

using System;
using Dtls.Internal;
using Xunit;

namespace Dtls.UnitTests;

/// <summary>Round-trip tests for the DTLS 24-bit and 48-bit big-endian helpers.</summary>
public sealed class BinaryHelpersTests
{
    [Theory]
    [InlineData(0u)]
    [InlineData(1u)]
    [InlineData(0x123456u)]
    [InlineData(0xFFFFFFu)]
    public void UInt24_RoundTrips(uint value)
    {
        Span<byte> buffer = stackalloc byte[3];
        BinaryHelpers.WriteUInt24BigEndian(buffer, value);
        Assert.Equal(value, BinaryHelpers.ReadUInt24BigEndian(buffer));
    }

    [Fact]
    public void UInt24_IsBigEndian()
    {
        Span<byte> buffer = stackalloc byte[3];
        BinaryHelpers.WriteUInt24BigEndian(buffer, 0x123456u);
        Assert.Equal(0x12, buffer[0]);
        Assert.Equal(0x34, buffer[1]);
        Assert.Equal(0x56, buffer[2]);
    }

    [Fact]
    public void UInt24_Overflow_Throws()
    {
        byte[] buffer = new byte[3];
        Assert.Throws<ArgumentOutOfRangeException>(
            () => BinaryHelpers.WriteUInt24BigEndian(buffer, 0x1000000u));
    }

    [Theory]
    [InlineData(0ul)]
    [InlineData(1ul)]
    [InlineData(0x123456789ABCul)]
    [InlineData(0xFFFFFFFFFFFFul)]
    public void UInt48_RoundTrips(ulong value)
    {
        Span<byte> buffer = stackalloc byte[6];
        BinaryHelpers.WriteUInt48BigEndian(buffer, value);
        Assert.Equal(value, BinaryHelpers.ReadUInt48BigEndian(buffer));
    }

    [Fact]
    public void UInt48_IsBigEndian()
    {
        Span<byte> buffer = stackalloc byte[6];
        BinaryHelpers.WriteUInt48BigEndian(buffer, 0x010203040506ul);
        Assert.Equal(0x01, buffer[0]);
        Assert.Equal(0x06, buffer[5]);
    }

    [Fact]
    public void UInt48_Overflow_Throws()
    {
        byte[] buffer = new byte[6];
        Assert.Throws<ArgumentOutOfRangeException>(
            () => BinaryHelpers.WriteUInt48BigEndian(buffer, 0x1000000000000ul));
    }
}
