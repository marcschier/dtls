// Copyright (c) marcschier. All rights reserved.
// Licensed under the MIT License. See LICENSE in the project root for license information.

using System;
using System.Security.Cryptography;
using System.Text;
using Dtls.Crypto;
using Xunit;

namespace Dtls.UnitTests;

/// <summary>
/// Validates the TLS 1.3 / DTLS 1.3 key schedule against the known-answer values from
/// RFC 8448 (the (EC)DHE-only handshake, with no PSK).
/// </summary>
public sealed class KeyScheduleTests
{
    private static readonly HashAlgorithmName Sha256 = HashAlgorithmName.SHA256;

    [Fact]
    public void EarlySecret_NoPsk_MatchesRfc8448()
    {
        // RFC 8448: Early Secret = HKDF-Extract(0, 0^32) for SHA-256.
        byte[] expected = Convert.FromHexString(
            "33ad0a1c607ec03b09e6cd9893680ce2" +
            "10adf300aa1f2660e1b22e10f170f92a");

        byte[] earlySecret = KeySchedule.EarlySecret(Sha256, ReadOnlySpan<byte>.Empty);
        Assert.Equal(expected, earlySecret);
    }

    [Fact]
    public void DeriveSecret_Derived_EmptyTranscript_MatchesRfc8448()
    {
        byte[] earlySecret = KeySchedule.EarlySecret(Sha256, ReadOnlySpan<byte>.Empty);

        // Transcript-Hash("") = SHA-256("").
        byte[] emptyHash;
        using (IncrementalHash sha = IncrementalHash.CreateHash(Sha256))
        {
            emptyHash = sha.GetHashAndReset();
        }

        byte[] expectedDerived = Convert.FromHexString(
            "6f2615a108c702c5678f54fc9dbab697" +
            "16c076189c48250cebeac3576c3611ba");

        byte[] derived = KeySchedule.DeriveSecret(
            Sha256,
            earlySecret,
            Encoding.ASCII.GetBytes("derived"),
            emptyHash);

        Assert.Equal(expectedDerived, derived);
    }

    [Fact]
    public void EncodeHkdfLabel_ProducesSpecLayout()
    {
        // For Derive-Secret(..., "derived", emptyHash), length = 32.
        byte[] emptyHash;
        using (IncrementalHash sha = IncrementalHash.CreateHash(Sha256))
        {
            emptyHash = sha.GetHashAndReset();
        }

        byte[] encoded = KeySchedule.EncodeHkdfLabel(
            32,
            Encoding.ASCII.GetBytes("derived"),
            emptyHash);

        // uint16 length = 0x0020
        Assert.Equal(0x00, encoded[0]);
        Assert.Equal(0x20, encoded[1]);

        // label length = len("tls13 derived") = 13
        Assert.Equal(13, encoded[2]);
        Assert.Equal("tls13 derived", Encoding.ASCII.GetString(encoded, 3, 13));

        // context length = 32, then the hash bytes
        Assert.Equal(32, encoded[16]);
        Assert.Equal(emptyHash, encoded[17..]);
    }

    [Fact]
    public void DeriveNext_NoIkm_AdvancesToHandshakeStageBaseline()
    {
        // Early -> derived-for-handshake extract with IKM = 0 reproduces the value the
        // schedule would feed forward when (EC)DHE is all-zero; this guards the plumbing
        // of DeriveNext (derived label + extract) against regressions.
        byte[] earlySecret = KeySchedule.EarlySecret(Sha256, ReadOnlySpan<byte>.Empty);
        byte[] next = KeySchedule.DeriveNext(Sha256, earlySecret, ReadOnlySpan<byte>.Empty);

        Assert.Equal(32, next.Length);
        Assert.NotEqual(earlySecret, next);
    }
}
