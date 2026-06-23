using System.Security.Cryptography;
using Dtls.Crypto;
using Xunit;

namespace Dtls.UnitTests;

/// <summary>Descriptor checks for the three mandatory DTLS 1.3 cipher suites.</summary>
public sealed class Dtls13CipherSuiteTests
{
    [Theory]
    [InlineData(0x1301, 16)]
    [InlineData(0x1302, 32)]
    [InlineData(0x1303, 32)]
    public void TryGet_ReturnsExpectedGeometry(int id, int keyLength)
    {
        bool found = Dtls13CipherSuite.TryGet((ushort)id, out Dtls13CipherSuite suite);

        Assert.True(found);
        Assert.Equal((ushort)id, suite.Id);
        Assert.Equal(keyLength, suite.KeyLength);
        Assert.Equal(12, suite.IvLength);
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
