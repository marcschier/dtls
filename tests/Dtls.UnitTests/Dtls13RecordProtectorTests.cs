using System;
using Dtls.Crypto;
using Dtls.Protocol.V13;
using Xunit;

namespace Dtls.UnitTests;

/// <summary>
/// End-to-end record protection tests for <see cref="Dtls13RecordProtector"/>: AEAD
/// round-trips, authentication failures, sequence-number encryption, and anti-replay.
/// </summary>
public sealed class Dtls13RecordProtectorTests
{
    private const byte ApplicationData = 23;

    private static Dtls13RecordProtector CreateProtector(
        Dtls13CipherSuite suite,
        int connectionIdLength = 0)
    {
        byte[] trafficSecret = HexOrRepeat.Range(1, Hkdf.HashLength(suite.HashAlgorithm));
        Dtls13RecordKeys keys = Dtls13RecordKeys.Derive(suite, trafficSecret);
        return new Dtls13RecordProtector(keys, connectionIdLength);
    }

    [Theory]
    [InlineData(0x1301)]
    [InlineData(0x1302)]
    public void SealThenOpen_RoundTrips_EightBitSequence(int suiteId)
    {
        Dtls13CipherSuite.TryGet((ushort)suiteId, out Dtls13CipherSuite suite);
        using Dtls13RecordProtector protector = CreateProtector(suite);

        byte[] payload = HexOrRepeat.Range(0x30, 50);
        const ulong seq = 5;
        byte[] record = new byte[protector.GetSealedLength(0, seq, payload.Length)];

        int written = protector.Seal(0, seq, ApplicationData, payload, default, record);

        Assert.True(protector.TryOpen(
            record.AsSpan(0, written),
            out byte contentType,
            out byte[] recovered,
            out ulong recoveredSeq));

        Assert.Equal(ApplicationData, contentType);
        Assert.Equal(payload, recovered);
        Assert.Equal(seq, recoveredSeq);
    }

    [Theory]
    [InlineData(0x1301)]
    [InlineData(0x1302)]
    public void SealThenOpen_RoundTrips_SixteenBitSequence(int suiteId)
    {
        Dtls13CipherSuite.TryGet((ushort)suiteId, out Dtls13CipherSuite suite);
        using Dtls13RecordProtector protector = CreateProtector(suite);

        byte[] payload = HexOrRepeat.Range(0x10, 17);
        const ulong seq = 300;
        byte[] record = new byte[protector.GetSealedLength(0, seq, payload.Length)];

        int written = protector.Seal(3, seq, ApplicationData, payload, default, record);

        Assert.True(protector.TryOpen(
            record.AsSpan(0, written),
            out byte contentType,
            out byte[] recovered,
            out ulong recoveredSeq));

        Assert.Equal(ApplicationData, contentType);
        Assert.Equal(payload, recovered);
        Assert.Equal(seq, recoveredSeq);
    }

    [Fact]
    public void Seal_EncryptsSequenceNumberOnWire()
    {
        using Dtls13RecordProtector protector = CreateProtector(Dtls13CipherSuite.Aes128GcmSha256);

        byte[] payload = HexOrRepeat.Range(0, 32);
        const ulong seq = 0x42;
        byte[] record = new byte[protector.GetSealedLength(0, seq, payload.Length)];
        protector.Seal(0, seq, ApplicationData, payload, default, record);

        // The on-wire sequence-number byte (index 1) must not equal the plaintext value.
        Assert.NotEqual((byte)seq, record[1]);
    }

    [Fact]
    public void SealThenOpen_WithConnectionId_RoundTrips()
    {
        byte[] cid = { 0x01, 0x02, 0x03, 0x04 };
        using Dtls13RecordProtector protector =
            CreateProtector(Dtls13CipherSuite.Aes128GcmSha256, cid.Length);

        byte[] payload = HexOrRepeat.Range(0x55, 40);
        const ulong seq = 9;
        byte[] record = new byte[protector.GetSealedLength(cid.Length, seq, payload.Length)];

        int written = protector.Seal(1, seq, ApplicationData, payload, cid, record);

        Assert.True(protector.TryOpen(
            record.AsSpan(0, written),
            out byte contentType,
            out byte[] recovered,
            out ulong recoveredSeq));

        Assert.Equal(ApplicationData, contentType);
        Assert.Equal(payload, recovered);
        Assert.Equal(seq, recoveredSeq);
    }

    [Theory]
    [InlineData(0x1301)]
    [InlineData(0x1302)]
    public void TryOpen_FailsWhenAnyByteFlipped(int suiteId)
    {
        Dtls13CipherSuite.TryGet((ushort)suiteId, out Dtls13CipherSuite suite);

        byte[] payload = HexOrRepeat.Range(0x20, 30);
        const ulong seq = 7;

        byte[] sealedRecord;
        int written;
        using (Dtls13RecordProtector sealer = CreateProtector(suite))
        {
            sealedRecord = new byte[sealer.GetSealedLength(0, seq, payload.Length)];
            written = sealer.Seal(0, seq, ApplicationData, payload, default, sealedRecord);
        }

        for (int i = 0; i < written; i++)
        {
            byte[] corrupted = sealedRecord.AsSpan(0, written).ToArray();
            corrupted[i] ^= 0xFF;

            using Dtls13RecordProtector opener = CreateProtector(suite);
            bool opened = opener.TryOpen(corrupted, out _, out _, out _);

            Assert.False(opened);
        }
    }

    [Fact]
    public void TryOpen_RejectsReplay()
    {
        using Dtls13RecordProtector protector = CreateProtector(Dtls13CipherSuite.Aes128GcmSha256);

        byte[] payload = HexOrRepeat.Range(0, 16);
        const ulong seq = 11;
        byte[] record = new byte[protector.GetSealedLength(0, seq, payload.Length)];
        int written = protector.Seal(0, seq, ApplicationData, payload, default, record);

        Assert.True(protector.TryOpen(record.AsSpan(0, written), out _, out _, out _));

        // Replaying the identical record must be rejected.
        Assert.False(protector.TryOpen(record.AsSpan(0, written), out _, out _, out _));
    }

    [Fact]
    public void Seal_ChaChaSuite_ThrowsNotSupported()
    {
        using Dtls13RecordProtector protector =
            CreateProtector(Dtls13CipherSuite.ChaCha20Poly1305Sha256);

        byte[] payload = HexOrRepeat.Range(0, 16);
        byte[] record = new byte[protector.GetSealedLength(0, 1, payload.Length)];

        Assert.Throws<NotSupportedException>(() =>
            protector.Seal(0, 1, ApplicationData, payload, default, record));
    }

#if NET8_0_OR_GREATER
    [Theory]
    [InlineData(0x1304)]
    [InlineData(0x1305)]
    public void SealThenOpen_CcmSuites_RoundTrip(int suiteId)
    {
        if (!System.Security.Cryptography.AesCcm.IsSupported)
        {
            return;
        }

        Dtls13CipherSuite.TryGet((ushort)suiteId, out Dtls13CipherSuite suite);
        using Dtls13RecordProtector protector = CreateProtector(suite);

        byte[] payload = HexOrRepeat.Range(0x40, 48);
        const ulong seq = 6;
        byte[] record = new byte[protector.GetSealedLength(0, seq, payload.Length)];

        int written = protector.Seal(0, seq, ApplicationData, payload, default, record);

        Assert.True(protector.TryOpen(
            record.AsSpan(0, written),
            out byte contentType,
            out byte[] recovered,
            out ulong recoveredSeq));

        Assert.Equal(ApplicationData, contentType);
        Assert.Equal(payload, recovered);
        Assert.Equal(seq, recoveredSeq);
    }

    [Theory]
    [InlineData(0)]
    [InlineData(1)]
    [InlineData(6)]
    public void SealThenOpen_Ccm8_TinyPayload_PadsToBlock(int payloadLength)
    {
        if (!System.Security.Cryptography.AesCcm.IsSupported)
        {
            return;
        }

        // CCM-8 has an 8-byte tag, so tiny payloads need zero padding to reach the 16-byte
        // minimum sealed length required by sequence-number masking.
        Dtls13CipherSuite.TryGet(0x1305, out Dtls13CipherSuite suite);
        using Dtls13RecordProtector protector = CreateProtector(suite);

        byte[] payload = HexOrRepeat.Range(0x70, payloadLength);
        const ulong seq = 4;
        int sealedLength = protector.GetSealedLength(0, seq, payload.Length);
        byte[] record = new byte[sealedLength];

        int written = protector.Seal(0, seq, ApplicationData, payload, default, record);

        // The encrypted portion (sealed length minus the 1-byte unified header prefix and
        // the short sequence number) must be at least one AES block.
        Assert.True(written >= SequenceNumberEncryptor.BlockLength);

        Assert.True(protector.TryOpen(
            record.AsSpan(0, written),
            out byte contentType,
            out byte[] recovered,
            out ulong recoveredSeq));

        Assert.Equal(ApplicationData, contentType);
        Assert.Equal(payload, recovered);
        Assert.Equal(seq, recoveredSeq);
    }
#endif
}
