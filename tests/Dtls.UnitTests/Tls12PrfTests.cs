using System;
using System.Globalization;
using System.Security.Cryptography;
using Dtls.Crypto;
using Xunit;

namespace Dtls.UnitTests;

/// <summary>
/// Tests the TLS 1.2 PRF (RFC 5246 section 5) against the widely published SHA-256 test vector.
/// </summary>
public sealed class Tls12PrfTests
{
    [Fact]
    public void Prf_Sha256_MatchesKnownVector()
    {
        byte[] secret = FromHex("9bbe436ba940f017b17652849a71db35");
        byte[] seed = FromHex("a0ba9f936cda311827a6f796ffd5198c");
        byte[] expected = FromHex(
            "e3f229ba727be17b8d122620557cd453c2aab21d07c3d495329b52d4e61edb5a6b301791e90d35c9"
            + "c9a46b4e14baf9af0fa022f7077def17abfd3797c0564bab4fbc91666e9def9b97fce34f796789baa4"
            + "8082d122ee42c5a72e5a5110fff70187347b66");

        byte[] actual = Tls12Prf.Prf(
            HashAlgorithmName.SHA256, secret, "test label", seed, expected.Length);

        Assert.Equal(expected, actual);
    }

    [Fact]
    public void Prf_ProducesRequestedLength_AndIsDeterministic()
    {
        byte[] secret = FromHex("0102030405060708");
        byte[] seed = FromHex("aabbccdd");

        byte[] a = Tls12Prf.Prf(HashAlgorithmName.SHA384, secret, "key expansion", seed, 72);
        byte[] b = Tls12Prf.Prf(HashAlgorithmName.SHA384, secret, "key expansion", seed, 72);

        Assert.Equal(72, a.Length);
        Assert.Equal(a, b);
    }

    [Fact]
    public void Prf_DifferentLabel_ProducesDifferentOutput()
    {
        byte[] secret = FromHex("0102030405060708");
        byte[] seed = FromHex("aabbccdd");

        byte[] a = Tls12Prf.Prf(HashAlgorithmName.SHA256, secret, "master secret", seed, 48);
        byte[] b = Tls12Prf.Prf(
            HashAlgorithmName.SHA256, secret, "extended master secret", seed, 48);

        Assert.NotEqual(a, b);
    }

    private static byte[] FromHex(string hex)
    {
        byte[] bytes = new byte[hex.Length / 2];
        for (int i = 0; i < bytes.Length; i++)
        {
            bytes[i] = byte.Parse(
                hex.AsSpan(i * 2, 2), NumberStyles.HexNumber, CultureInfo.InvariantCulture);
        }

        return bytes;
    }
}
