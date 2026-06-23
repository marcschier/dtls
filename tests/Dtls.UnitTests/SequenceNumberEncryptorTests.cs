using System;
using Dtls.Crypto;
using Xunit;

namespace Dtls.UnitTests;

/// <summary>
/// Tests the RFC 9147 section 4.2.3 sequence-number masking primitive.
/// </summary>
public sealed class SequenceNumberEncryptorTests
{
    [Fact]
    public void Mask_IsDeterministic()
    {
        using SequenceNumberEncryptor encryptor = new(
            Dtls13CipherSuite.Aes128GcmSha256,
            HexOrRepeat.Range(1, 16));

        byte[] sample = HexOrRepeat.Range(0, 16);

        byte[] first = new byte[2];
        byte[] second = new byte[2];
        encryptor.Mask(sample, first);
        encryptor.Mask(sample, second);

        Assert.Equal(first, second);
    }

    [Fact]
    public void Mask_ThenUnmask_RecoversSequenceNumber()
    {
        using SequenceNumberEncryptor encryptor = new(
            Dtls13CipherSuite.Aes256GcmSha384,
            HexOrRepeat.Range(5, 32));

        byte[] sample = HexOrRepeat.Range(40, 16);
        const ushort original = 0x9ABC;

        Span<byte> mask = stackalloc byte[2];
        encryptor.Mask(sample, mask);

        int encrypted = original ^ ((mask[0] << 8) | mask[1]);
        Assert.NotEqual(original, (ushort)encrypted);

        int decrypted = encrypted ^ ((mask[0] << 8) | mask[1]);
        Assert.Equal(original, (ushort)(decrypted & 0xFFFF));
    }

    [Fact]
    public void Mask_DiffersBetweenKeys()
    {
        byte[] sample = HexOrRepeat.Range(0, 16);

        byte[] maskA = new byte[2];
        byte[] maskB = new byte[2];

        using (SequenceNumberEncryptor a = new(
            Dtls13CipherSuite.Aes128GcmSha256,
            HexOrRepeat.Range(1, 16)))
        {
            a.Mask(sample, maskA);
        }

        using (SequenceNumberEncryptor b = new(
            Dtls13CipherSuite.Aes128GcmSha256,
            HexOrRepeat.Range(9, 16)))
        {
            b.Mask(sample, maskB);
        }

        Assert.NotEqual(maskA, maskB);
    }

    [Fact]
    public void Mask_ChaCha_ThrowsNotSupported()
    {
        using SequenceNumberEncryptor encryptor = new(
            Dtls13CipherSuite.ChaCha20Poly1305Sha256,
            HexOrRepeat.Range(1, 32));

        byte[] sample = HexOrRepeat.Range(0, 16);
        byte[] mask = new byte[1];

        Assert.Throws<NotSupportedException>(() => encryptor.Mask(sample, mask));
    }
}
