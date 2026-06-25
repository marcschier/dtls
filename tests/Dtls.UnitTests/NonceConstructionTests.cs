// Copyright (c) marcschier. All rights reserved.
// Licensed under the MIT License. See LICENSE in the project root for license information.

using System;
using Dtls.Crypto;
using Xunit;

namespace Dtls.UnitTests;

/// <summary>
/// Validates the per-record AEAD nonce construction (RFC 8446 section 5.3,
/// RFC 9147 section 5.1): <c>write_iv XOR (sequence_number padded big-endian)</c>.
/// </summary>
public sealed class NonceConstructionTests
{
    [Fact]
    public void ComputeNonce_XorsSequenceNumberIntoLowEightBytes()
    {
        byte[] writeIv = Convert.FromHexString("000102030405060708090a0b");
        const ulong sequenceNumber = 0x1122334455667788UL;

        Span<byte> nonce = stackalloc byte[12];
        Dtls13RecordKeys.ComputeNonce(writeIv, sequenceNumber, nonce);

        byte[] expected = Convert.FromHexString("0001020315273543" + "5d6f7d83");
        Assert.Equal(expected, nonce.ToArray());
    }

    [Fact]
    public void ComputeNonce_SequenceZero_ReturnsWriteIv()
    {
        byte[] writeIv = Convert.FromHexString("0a0b0c0d0e0f101112131415");

        Span<byte> nonce = stackalloc byte[12];
        Dtls13RecordKeys.ComputeNonce(writeIv, 0, nonce);

        Assert.Equal(writeIv, nonce.ToArray());
    }

    [Fact]
    public void ComputeNonce_OnlyLowEightBytesAffected()
    {
        byte[] writeIv = Convert.FromHexString("ffffffffffffffffffffffff");

        Span<byte> nonce = stackalloc byte[12];
        Dtls13RecordKeys.ComputeNonce(writeIv, 1, nonce);

        // Top four bytes unchanged; the low byte flips from 0xFF to 0xFE.
        byte[] expected = Convert.FromHexString("fffffffffffffffffffffffe");
        Assert.Equal(expected, nonce.ToArray());
    }

    [Fact]
    public void ComputeNonce_RejectsWrongLengthIv()
    {
        byte[] shortIv = new byte[11];
        Assert.Throws<ArgumentException>(() =>
        {
            byte[] nonce = new byte[12];
            Dtls13RecordKeys.ComputeNonce(shortIv, 0, nonce);
        });
    }
}
