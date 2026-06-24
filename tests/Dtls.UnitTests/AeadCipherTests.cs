using System;
using Dtls.Crypto;
using Xunit;

namespace Dtls.UnitTests;

/// <summary>
/// AEAD wrapper round-trips for the BCL-backed AES-GCM and ChaCha20-Poly1305 primitives.
/// </summary>
public sealed class AeadCipherTests
{
    [Fact]
    public void AesGcm128_SealOpen_RoundTrips()
    {
        AssertRoundTrip(new AesGcmCipher(HexOrRepeat.Range(1, 16)));
    }

    [Fact]
    public void AesGcm256_SealOpen_RoundTrips()
    {
        AssertRoundTrip(new AesGcmCipher(HexOrRepeat.Range(1, 32)));
    }

    [Fact]
    public void ChaCha20Poly1305_SealOpen_RoundTrips()
    {
        AssertRoundTrip(new ChaCha20Poly1305Cipher(HexOrRepeat.Range(7, 32)));
    }

    [Fact]
    public void AesGcm_TamperedTag_FailsToOpen()
    {
        using AesGcmCipher cipher = new(HexOrRepeat.Range(3, 16));
        byte[] nonce = HexOrRepeat.Range(0, 12);
        byte[] plaintext = HexOrRepeat.Range(10, 20);
        byte[] aad = HexOrRepeat.Range(50, 5);

        byte[] sealed1 = new byte[plaintext.Length + cipher.TagLength];
        cipher.Seal(nonce, plaintext, aad, sealed1);
        sealed1[^1] ^= 0xFF;

        byte[] recovered = new byte[plaintext.Length];
        Assert.False(cipher.Open(nonce, sealed1, aad, recovered));
    }

#if NET8_0_OR_GREATER
    [Fact]
    public void AesCcm128_SealOpen_RoundTrips()
    {
        AssertRoundTrip(new AesCcmCipher(HexOrRepeat.Range(2, 16), 16));
    }

    [Fact]
    public void AesCcm8_SealOpen_RoundTrips()
    {
        AssertRoundTrip(new AesCcmCipher(HexOrRepeat.Range(4, 16), 8));
    }

    [Theory]
    [InlineData(16)]
    [InlineData(8)]
    public void AesCcm_TamperedTag_FailsToOpen(int tagLength)
    {
        using AesCcmCipher cipher = new(HexOrRepeat.Range(6, 16), tagLength);
        byte[] nonce = HexOrRepeat.Range(0, 12);
        byte[] plaintext = HexOrRepeat.Range(10, 20);
        byte[] aad = HexOrRepeat.Range(50, 5);

        byte[] sealed1 = new byte[plaintext.Length + cipher.TagLength];
        cipher.Seal(nonce, plaintext, aad, sealed1);
        sealed1[^1] ^= 0xFF;

        Assert.Equal(tagLength, cipher.TagLength);
        byte[] recovered = new byte[plaintext.Length];
        Assert.False(cipher.Open(nonce, sealed1, aad, recovered));
    }
#endif

    private static void AssertRoundTrip(IAeadCipher cipher)
    {
        using (cipher)
        {
            byte[] nonce = HexOrRepeat.Range(0, 12);
            byte[] plaintext = HexOrRepeat.Range(100, 40);
            byte[] aad = HexOrRepeat.Range(1, 13);

            byte[] sealed1 = new byte[plaintext.Length + cipher.TagLength];
            cipher.Seal(nonce, plaintext, aad, sealed1);

            Assert.NotEqual(plaintext, sealed1[..plaintext.Length]);

            byte[] recovered = new byte[plaintext.Length];
            Assert.True(cipher.Open(nonce, sealed1, aad, recovered));
            Assert.Equal(plaintext, recovered);

            // Wrong AAD fails authentication.
            byte[] wrongAad = HexOrRepeat.Range(2, 13);
            Assert.False(cipher.Open(nonce, sealed1, wrongAad, recovered));
        }
    }
}
