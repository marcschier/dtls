using System.Security.Cryptography;
using Dtls.Crypto;
using Xunit;

namespace Dtls.UnitTests;

/// <summary>Descriptor checks for the three mandatory DTLS 1.3 cipher suites.</summary>
public sealed class Dtls13CipherSuiteTests
{
    [Theory]
    [InlineData(0x1301, 16, 16)]
    [InlineData(0x1302, 32, 16)]
    [InlineData(0x1303, 32, 16)]
    public void TryGet_ReturnsExpectedGeometry(int id, int keyLength, int tagLength)
    {
        bool found = Dtls13CipherSuite.TryGet((ushort)id, out Dtls13CipherSuite suite);

        Assert.True(found);
        Assert.Equal((ushort)id, suite.Id);
        Assert.Equal(keyLength, suite.KeyLength);
        Assert.Equal(12, suite.IvLength);
        Assert.Equal(tagLength, suite.TagLength);
    }

#if NET8_0_OR_GREATER
    [Theory]
    [InlineData(0x1304, 16, 16)]
    [InlineData(0x1305, 16, 8)]
    public void TryGet_Ccm_ReturnsExpectedGeometry(int id, int keyLength, int tagLength)
    {
        bool found = Dtls13CipherSuite.TryGet((ushort)id, out Dtls13CipherSuite suite);

        Assert.True(found);
        Assert.Equal((ushort)id, suite.Id);
        Assert.Equal(keyLength, suite.KeyLength);
        Assert.Equal(12, suite.IvLength);
        Assert.Equal(tagLength, suite.TagLength);
        Assert.Equal(HashAlgorithmName.SHA256, suite.HashAlgorithm);
        Assert.Equal(Dtls13AeadKind.AesCcm, suite.Aead);
    }

    [Fact]
    public void SupportedDefault_IncludesCcm_OnNet8Plus()
    {
        ushort[] ids = ToIds(Dtls13CipherSuite.SupportedDefault);
        Assert.Equal(new ushort[] { 0x1301, 0x1302, 0x1304, 0x1305 }, ids);
        Assert.True(Dtls13CipherSuite.IsSupported(0x1304));
        Assert.True(Dtls13CipherSuite.IsSupported(0x1305));
    }
#else
    [Fact]
    public void SupportedDefault_ExcludesCcm_OnNetStandard()
    {
        ushort[] ids = ToIds(Dtls13CipherSuite.SupportedDefault);
        Assert.Equal(new ushort[] { 0x1301, 0x1302 }, ids);
        Assert.False(Dtls13CipherSuite.IsSupported(0x1304));
        Assert.False(Dtls13CipherSuite.IsSupported(0x1305));
    }
#endif

    private static ushort[] ToIds(
        System.Collections.Generic.IReadOnlyList<Dtls13CipherSuite> suites)
    {
        ushort[] ids = new ushort[suites.Count];
        for (int i = 0; i < suites.Count; i++)
        {
            ids[i] = suites[i].Id;
        }

        return ids;
    }

    [Fact]
    public void Aes128_UsesSha256()
    {
        Assert.Equal(HashAlgorithmName.SHA256, Dtls13CipherSuite.Aes128GcmSha256.HashAlgorithm);
        Assert.Equal(Dtls13AeadKind.AesGcm, Dtls13CipherSuite.Aes128GcmSha256.Aead);
    }

    [Fact]
    public void Aes256_UsesSha384()
    {
        Assert.Equal(HashAlgorithmName.SHA384, Dtls13CipherSuite.Aes256GcmSha384.HashAlgorithm);
        Assert.Equal(Dtls13AeadKind.AesGcm, Dtls13CipherSuite.Aes256GcmSha384.Aead);
    }

    [Fact]
    public void ChaCha_UsesSha256()
    {
        Assert.Equal(
            HashAlgorithmName.SHA256,
            Dtls13CipherSuite.ChaCha20Poly1305Sha256.HashAlgorithm);
        Assert.Equal(
            Dtls13AeadKind.ChaCha20Poly1305,
            Dtls13CipherSuite.ChaCha20Poly1305Sha256.Aead);
    }

    [Fact]
    public void TryGet_UnknownId_ReturnsFalse()
    {
        Assert.False(Dtls13CipherSuite.TryGet(0x0000, out _));
    }
}
