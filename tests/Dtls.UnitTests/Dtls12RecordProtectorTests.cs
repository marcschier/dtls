using System;
using System.Security.Cryptography;
using Dtls.Crypto;
using Dtls.Protocol.V12;
using Xunit;

namespace Dtls.UnitTests;

/// <summary>
/// Tests the DTLS 1.2 AEAD record protector (RFC 6347 / RFC 5288): seal/open round-trips across
/// suites, and rejection of tampered records and records opened under the wrong key.
/// </summary>
public sealed class Dtls12RecordProtectorTests
{
    [Theory]
    [InlineData((ushort)0xC02B)] // ECDHE-ECDSA AES-128-GCM
    [InlineData((ushort)0xC02C)] // ECDHE-ECDSA AES-256-GCM
    [InlineData((ushort)0xC0AC)] // ECDHE-ECDSA AES-128-CCM
    [InlineData((ushort)0xC0A8)] // PSK AES-128-CCM-8
    public void SealOpen_RoundTrips(ushort suiteId)
    {
        if (!Dtls12CipherSuite.TryGet(suiteId, out Dtls12CipherSuite suite))
        {
            // AES-CCM is unavailable on some platforms (for example macOS); skip there.
            return;
        }

        byte[] key = RandomNumberGenerator.GetBytes(suite.KeyLength);
        byte[] salt = RandomNumberGenerator.GetBytes(Dtls12CipherSuite.SaltLength);

        using Dtls12RecordProtector sender = new(suite, key, salt);
        using Dtls12RecordProtector receiver = new(suite, key, salt);

        byte[] plaintext = RandomNumberGenerator.GetBytes(120);
        const byte contentType = 23; // application_data
        const ushort epoch = 1;
        const ulong sequence = 0x0000_00AB_CDEF_0042 & 0xFFFFFFFFFFFF;

        byte[] record = new byte[sender.GetSealedLength(plaintext.Length)];
        int written = sender.Seal(epoch, sequence, contentType, plaintext, record);
        Assert.Equal(record.Length, written);

        Assert.True(receiver.TryOpen(
            record, out byte openedType, out byte[] opened, out ushort openedEpoch,
            out ulong openedSeq, out int consumed));
        Assert.Equal(contentType, openedType);
        Assert.Equal(epoch, openedEpoch);
        Assert.Equal(sequence, openedSeq);
        Assert.Equal(record.Length, consumed);
        Assert.Equal(plaintext, opened);
    }

    [Fact]
    public void TryOpen_TamperedCiphertext_Fails()
    {
        Assert.True(Dtls12CipherSuite.TryGet(0xC02F, out Dtls12CipherSuite suite));
        byte[] key = RandomNumberGenerator.GetBytes(suite.KeyLength);
        byte[] salt = RandomNumberGenerator.GetBytes(Dtls12CipherSuite.SaltLength);

        using Dtls12RecordProtector protector = new(suite, key, salt);
        byte[] plaintext = RandomNumberGenerator.GetBytes(40);
        byte[] record = new byte[protector.GetSealedLength(plaintext.Length)];
        protector.Seal(1, 7, 23, plaintext, record);

        record[^1] ^= 0xFF;

        Assert.False(protector.TryOpen(record, out _, out _, out _, out _, out _));
    }

    [Fact]
    public void TryOpen_WrongKey_Fails()
    {
        Assert.True(Dtls12CipherSuite.TryGet(0xC030, out Dtls12CipherSuite suite));
        byte[] salt = RandomNumberGenerator.GetBytes(Dtls12CipherSuite.SaltLength);

        using Dtls12RecordProtector sender = new(
            suite, RandomNumberGenerator.GetBytes(suite.KeyLength), salt);
        using Dtls12RecordProtector wrong = new(
            suite, RandomNumberGenerator.GetBytes(suite.KeyLength), salt);

        byte[] plaintext = RandomNumberGenerator.GetBytes(64);
        byte[] record = new byte[sender.GetSealedLength(plaintext.Length)];
        sender.Seal(1, 1, 22, plaintext, record);

        Assert.False(wrong.TryOpen(record, out _, out _, out _, out _, out _));
    }

    [Fact]
    public void Seal_DistinctSequences_ProduceDistinctRecords()
    {
        Assert.True(Dtls12CipherSuite.TryGet(0xC02B, out Dtls12CipherSuite suite));
        byte[] key = RandomNumberGenerator.GetBytes(suite.KeyLength);
        byte[] salt = RandomNumberGenerator.GetBytes(Dtls12CipherSuite.SaltLength);
        using Dtls12RecordProtector protector = new(suite, key, salt);

        byte[] plaintext = new byte[32];
        byte[] r0 = new byte[protector.GetSealedLength(plaintext.Length)];
        byte[] r1 = new byte[protector.GetSealedLength(plaintext.Length)];
        protector.Seal(1, 0, 23, plaintext, r0);
        protector.Seal(1, 1, 23, plaintext, r1);

        Assert.NotEqual(r0, r1);
    }
}
