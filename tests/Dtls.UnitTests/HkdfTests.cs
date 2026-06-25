// Copyright (c) marcschier. All rights reserved.
// Licensed under the MIT License. See LICENSE in the project root for license information.

using System;
using System.Security.Cryptography;
using Dtls.Crypto;
using Xunit;

namespace Dtls.UnitTests;

/// <summary>
/// Validates the HKDF implementation against the official RFC 5869 test vectors.
/// </summary>
public sealed class HkdfTests
{
    [Fact]
    public void Rfc5869_TestCase1_Sha256_Extract_And_Expand()
    {
        byte[] ikm = HexOrRepeat.Repeat(0x0b, 22);
        byte[] salt = Convert.FromHexString("000102030405060708090a0b0c");
        byte[] info = Convert.FromHexString("f0f1f2f3f4f5f6f7f8f9");
        const int length = 42;

        byte[] expectedPrk = Convert.FromHexString(
            "077709362c2e32df0ddc3f0dc47bba6390b6c73bb50f9c3122ec844ad7c2b3e5");
        byte[] expectedOkm = Convert.FromHexString(
            "3cb25f25faacd57a90434f64d0362f2a" +
            "2d2d0a90cf1a5a4c5db02d56ecc4c5bf" +
            "34007208d5b887185865");

        byte[] prk = Hkdf.Extract(HashAlgorithmName.SHA256, salt, ikm);
        Assert.Equal(expectedPrk, prk);

        byte[] okm = Hkdf.Expand(HashAlgorithmName.SHA256, prk, info, length);
        Assert.Equal(expectedOkm, okm);
    }

    [Fact]
    public void Rfc5869_TestCase2_Sha256_LongInputs()
    {
        byte[] ikm = HexOrRepeat.Range(0x00, 80);
        byte[] salt = HexOrRepeat.Range(0x60, 80);
        byte[] info = HexOrRepeat.Range(0xb0, 80);
        const int length = 82;

        byte[] expectedOkm = Convert.FromHexString(
            "b11e398dc80327a1c8e7f78c596a4934" +
            "4f012eda2d4efad8a050cc4c19afa97c" +
            "59045a99cac7827271cb41c65e590e09" +
            "da3275600c2f09b8367793a9aca3db71" +
            "cc30c58179ec3e87c14c01d5c1f3434f" +
            "1d87");

        byte[] prk = Hkdf.Extract(HashAlgorithmName.SHA256, salt, ikm);
        byte[] okm = Hkdf.Expand(HashAlgorithmName.SHA256, prk, info, length);
        Assert.Equal(expectedOkm, okm);
    }

    [Fact]
    public void Rfc5869_TestCase3_Sha256_ZeroLengthSaltAndInfo()
    {
        byte[] ikm = HexOrRepeat.Repeat(0x0b, 22);
        const int length = 42;

        byte[] expectedOkm = Convert.FromHexString(
            "8da4e775a563c18f715f802a063c5a31" +
            "b8a11f5c5ee1879ec3454e5f3c738d2d" +
            "9d201395faa4b61a96c8");

        byte[] prk = Hkdf.Extract(HashAlgorithmName.SHA256, ReadOnlySpan<byte>.Empty, ikm);
        byte[] okm = Hkdf.Expand(
            HashAlgorithmName.SHA256,
            prk,
            ReadOnlySpan<byte>.Empty,
            length);
        Assert.Equal(expectedOkm, okm);
    }

    [Fact]
    public void HashLength_ReturnsExpected()
    {
        Assert.Equal(32, Hkdf.HashLength(HashAlgorithmName.SHA256));
        Assert.Equal(48, Hkdf.HashLength(HashAlgorithmName.SHA384));
        Assert.Equal(64, Hkdf.HashLength(HashAlgorithmName.SHA512));
    }
}
