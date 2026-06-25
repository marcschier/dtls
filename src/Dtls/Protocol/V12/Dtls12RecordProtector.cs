using System;
using System.Buffers.Binary;
using System.Security.Cryptography;
using Dtls.Crypto;
using Dtls.Internal;
using Dtls.Protocol.V13;
using Dtls.Protocol.V13.Handshake;

namespace Dtls.Protocol.V12;

/// <summary>
/// Protects and unprotects DTLS 1.2 AEAD records (RFC 6347 section 4.1, RFC 5246 section 6.2.3.3,
/// RFC 5288). Unlike DTLS 1.3, the epoch and 48-bit sequence number are carried in the cleartext
/// record header (no sequence-number encryption), and each record carries an explicit 8-byte nonce.
/// The AEAD nonce is <c>salt(4) || explicit_nonce(8)</c>; the additional data is
/// <c>seq_num(8) || type(1) || version(2) || length(2)</c> where <c>seq_num = epoch(16) ||
/// sequence_number(48)</c> and <c>length</c> is the plaintext length. The explicit nonce sent on
/// the wire is the record's 64-bit (epoch||sequence) value, which is unique per record.
/// </summary>
internal sealed class Dtls12RecordProtector : IDisposable
{
    private const int ExplicitNonceLength = Dtls12CipherSuite.ExplicitNonceLength;
    private const int SaltLength = Dtls12CipherSuite.SaltLength;
    private const int NonceLength = SaltLength + ExplicitNonceLength;

    private readonly IAeadCipher _aead;
    private readonly byte[] _salt;
    private readonly int _tagLength;
    private bool _disposed;

    public Dtls12RecordProtector(
        Dtls12CipherSuite suite,
        ReadOnlySpan<byte> writeKey,
        ReadOnlySpan<byte> writeSalt)
    {
        if (writeSalt.Length != SaltLength)
        {
            throw new ArgumentException("DTLS 1.2 write salt must be 4 bytes.", nameof(writeSalt));
        }

        _aead = CreateAead(suite, writeKey);
        _salt = writeSalt.ToArray();
        _tagLength = suite.TagLength;
    }

    /// <summary>The sealed record length for a plaintext of the given length.</summary>
    public int GetSealedLength(int plaintextLength) =>
        Dtls13PlaintextRecord.HeaderLength + ExplicitNonceLength + plaintextLength + _tagLength;

    /// <summary>
    /// Seals one record into <paramref name="destination"/> and returns the bytes written.
    /// </summary>
    public int Seal(
        ushort epoch,
        ulong sequenceNumber,
        byte contentType,
        ReadOnlySpan<byte> plaintext,
        Span<byte> destination)
    {
        if (plaintext.Length > ushort.MaxValue)
        {
            throw new ArgumentException("DTLS 1.2 record plaintext too large.", nameof(plaintext));
        }

        Span<byte> explicitNonce = stackalloc byte[ExplicitNonceLength];
        WriteRecordSeqNum(epoch, sequenceNumber, explicitNonce);

        Span<byte> nonce = stackalloc byte[NonceLength];
        _salt.CopyTo(nonce);
        explicitNonce.CopyTo(nonce.Slice(SaltLength));

        Span<byte> aad = stackalloc byte[13];
        BuildAad(epoch, sequenceNumber, contentType, plaintext.Length, aad);

        int fragmentLength = ExplicitNonceLength + plaintext.Length + _tagLength;
        WriteHeader(destination, contentType, epoch, sequenceNumber, fragmentLength);

        int fragmentOffset = Dtls13PlaintextRecord.HeaderLength;
        explicitNonce.CopyTo(destination.Slice(fragmentOffset, ExplicitNonceLength));
        _aead.Seal(
            nonce,
            plaintext,
            aad,
            destination.Slice(
                fragmentOffset + ExplicitNonceLength, plaintext.Length + _tagLength));

        return Dtls13PlaintextRecord.HeaderLength + fragmentLength;
    }

    /// <summary>
    /// Opens one record from the front of <paramref name="record"/>. On success returns the content
    /// type, the recovered plaintext, the record epoch and sequence number, and the bytes consumed.
    /// </summary>
    public bool TryOpen(
        ReadOnlySpan<byte> record,
        out byte contentType,
        out byte[] plaintext,
        out ushort epoch,
        out ulong sequenceNumber,
        out int consumed)
    {
        plaintext = Array.Empty<byte>();

        if (!Dtls13PlaintextRecord.TryParse(
                record,
                out contentType,
                out epoch,
                out sequenceNumber,
                out ReadOnlySpan<byte> fragment,
                out consumed))
        {
            return false;
        }

        if (fragment.Length < ExplicitNonceLength + _tagLength)
        {
            return false;
        }

        ReadOnlySpan<byte> explicitNonce = fragment.Slice(0, ExplicitNonceLength);
        ReadOnlySpan<byte> ciphertextAndTag = fragment.Slice(ExplicitNonceLength);
        int plaintextLength = ciphertextAndTag.Length - _tagLength;

        Span<byte> nonce = stackalloc byte[NonceLength];
        _salt.CopyTo(nonce);
        explicitNonce.CopyTo(nonce.Slice(SaltLength));

        Span<byte> aad = stackalloc byte[13];
        BuildAad(epoch, sequenceNumber, contentType, plaintextLength, aad);

        byte[] output = new byte[plaintextLength];
        if (!_aead.Open(nonce, ciphertextAndTag, aad, output))
        {
            return false;
        }

        plaintext = output;
        return true;
    }

    private static void WriteHeader(
        Span<byte> destination,
        byte contentType,
        ushort epoch,
        ulong sequenceNumber,
        int fragmentLength)
    {
        destination[0] = contentType;
        BinaryPrimitives.WriteUInt16BigEndian(destination.Slice(1, 2), DtlsWireVersion.Dtls12);
        BinaryPrimitives.WriteUInt16BigEndian(destination.Slice(3, 2), epoch);
        BinaryHelpers.WriteUInt48BigEndian(destination.Slice(5, 6), sequenceNumber);
        BinaryPrimitives.WriteUInt16BigEndian(destination.Slice(11, 2), (ushort)fragmentLength);
    }

    private static void BuildAad(
        ushort epoch,
        ulong sequenceNumber,
        byte contentType,
        int plaintextLength,
        Span<byte> aad)
    {
        WriteRecordSeqNum(epoch, sequenceNumber, aad.Slice(0, 8));
        aad[8] = contentType;
        BinaryPrimitives.WriteUInt16BigEndian(aad.Slice(9, 2), DtlsWireVersion.Dtls12);
        BinaryPrimitives.WriteUInt16BigEndian(aad.Slice(11, 2), (ushort)plaintextLength);
    }

    private static void WriteRecordSeqNum(
        ushort epoch,
        ulong sequenceNumber,
        Span<byte> destination)
    {
        ulong recordSeq = ((ulong)epoch << 48) | (sequenceNumber & 0xFFFFFFFFFFFFUL);
        BinaryPrimitives.WriteUInt64BigEndian(destination, recordSeq);
    }

    private static IAeadCipher CreateAead(Dtls12CipherSuite suite, ReadOnlySpan<byte> key)
    {
        IAeadCipher aead;
        switch (suite.Aead)
        {
            case Dtls13AeadKind.AesGcm:
                aead = new AesGcmCipher(key);
                break;
#if NET8_0_OR_GREATER
            case Dtls13AeadKind.AesCcm:
                aead = new AesCcmCipher(key, suite.TagLength);
                break;
#endif
            default:
                throw new NotSupportedException(
                    "Unsupported AEAD for DTLS 1.2: " + suite.Aead + ".");
        }

        return aead;
    }

    public void Dispose()
    {
        if (_disposed)
        {
            return;
        }

        _aead.Dispose();
        CryptographicOperations.ZeroMemory(_salt);
        _disposed = true;
    }
}
