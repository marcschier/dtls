using System;
using System.Buffers.Binary;
using System.Security.Cryptography;

namespace Dtls.Crypto;

/// <summary>
/// The per-record key material derived from a single DTLS 1.3 traffic secret
/// (RFC 9147 section 4 / RFC 8446 section 7.3). It holds the AEAD write key, the AEAD
/// write IV, and the sequence-number-encryption key, together with the cipher suite they
/// belong to. Key material is wiped on <see cref="Dispose"/>.
/// </summary>
internal sealed class Dtls13RecordKeys : IDisposable
{
    private static readonly byte[] KeyLabel = "key"u8.ToArray();
    private static readonly byte[] IvLabel = "iv"u8.ToArray();
    private static readonly byte[] SequenceNumberLabel = "sn"u8.ToArray();

    private readonly byte[] _writeKey;
    private readonly byte[] _writeIv;
    private readonly byte[] _sequenceNumberKey;
    private bool _disposed;

    private Dtls13RecordKeys(
        Dtls13CipherSuite cipherSuite,
        byte[] writeKey,
        byte[] writeIv,
        byte[] sequenceNumberKey)
    {
        CipherSuite = cipherSuite;
        _writeKey = writeKey;
        _writeIv = writeIv;
        _sequenceNumberKey = sequenceNumberKey;
    }

    /// <summary>The cipher suite these keys belong to.</summary>
    public Dtls13CipherSuite CipherSuite { get; }

    /// <summary>The AEAD record-protection key.</summary>
    public ReadOnlySpan<byte> WriteKey => _writeKey;

    /// <summary>The AEAD record-protection IV (12 bytes).</summary>
    public ReadOnlySpan<byte> WriteIv => _writeIv;

    /// <summary>The sequence-number-encryption key.</summary>
    public ReadOnlySpan<byte> SequenceNumberKey => _sequenceNumberKey;

    /// <summary>
    /// Derives the per-record key material from <paramref name="trafficSecret"/> using
    /// HKDF-Expand-Label with the <c>"key"</c>, <c>"iv"</c>, and <c>"sn"</c> labels.
    /// </summary>
    /// <param name="cipherSuite">The negotiated cipher suite.</param>
    /// <param name="trafficSecret">The traffic secret for this direction/epoch.</param>
    /// <returns>The derived record keys.</returns>
    public static Dtls13RecordKeys Derive(
        Dtls13CipherSuite cipherSuite,
        ReadOnlySpan<byte> trafficSecret)
    {
        HashAlgorithmName hash = cipherSuite.HashAlgorithm;

        byte[] writeKey = KeySchedule.ExpandLabel(
            hash,
            trafficSecret,
            KeyLabel,
            ReadOnlySpan<byte>.Empty,
            cipherSuite.KeyLength);

        byte[] writeIv = KeySchedule.ExpandLabel(
            hash,
            trafficSecret,
            IvLabel,
            ReadOnlySpan<byte>.Empty,
            cipherSuite.IvLength);

        byte[] sequenceNumberKey = KeySchedule.ExpandLabel(
            hash,
            trafficSecret,
            SequenceNumberLabel,
            ReadOnlySpan<byte>.Empty,
            cipherSuite.KeyLength);

        return new Dtls13RecordKeys(cipherSuite, writeKey, writeIv, sequenceNumberKey);
    }

    /// <summary>
    /// Computes the per-record AEAD nonce (RFC 8446 section 5.3, RFC 9147 section 5.1):
    /// <c>write_iv XOR (sequence_number padded big-endian to iv length)</c>.
    /// </summary>
    /// <param name="writeIv">The AEAD write IV (12 bytes).</param>
    /// <param name="sequenceNumber">The 64-bit record sequence number.</param>
    /// <param name="nonce">Receives the 12-byte nonce.</param>
    public static void ComputeNonce(
        ReadOnlySpan<byte> writeIv,
        ulong sequenceNumber,
        Span<byte> nonce)
    {
        if (writeIv.Length != Dtls13CipherSuite.FixedIvLength)
        {
            throw new ArgumentException(
                "The write IV must be 12 bytes.",
                nameof(writeIv));
        }

        if (nonce.Length != Dtls13CipherSuite.FixedIvLength)
        {
            throw new ArgumentException(
                "The nonce destination must be 12 bytes.",
                nameof(nonce));
        }

        writeIv.CopyTo(nonce);

        Span<byte> sequenceBytes = stackalloc byte[sizeof(ulong)];
        BinaryPrimitives.WriteUInt64BigEndian(sequenceBytes, sequenceNumber);

        int offset = nonce.Length - sizeof(ulong);
        for (int i = 0; i < sizeof(ulong); i++)
        {
            nonce[offset + i] ^= sequenceBytes[i];
        }
    }

    /// <summary>
    /// Computes the per-record AEAD nonce for this key set's write IV.
    /// </summary>
    /// <param name="sequenceNumber">The 64-bit record sequence number.</param>
    /// <param name="nonce">Receives the 12-byte nonce.</param>
    public void ComputeNonce(ulong sequenceNumber, Span<byte> nonce) =>
        ComputeNonce(_writeIv, sequenceNumber, nonce);

    /// <summary>Creates the AEAD primitive for this key set's write key.</summary>
    /// <returns>An <see cref="IAeadCipher"/> bound to the write key.</returns>
    public IAeadCipher CreateAead()
    {
        return CipherSuite.Aead switch
        {
            Dtls13AeadKind.AesGcm => new AesGcmCipher(_writeKey),
            Dtls13AeadKind.ChaCha20Poly1305 => new ChaCha20Poly1305Cipher(_writeKey),
            _ => throw new InvalidOperationException("Unknown AEAD kind."),
        };
    }

    /// <inheritdoc />
    public void Dispose()
    {
        if (_disposed)
        {
            return;
        }

        CryptographicOperations.ZeroMemory(_writeKey);
        CryptographicOperations.ZeroMemory(_writeIv);
        CryptographicOperations.ZeroMemory(_sequenceNumberKey);
        _disposed = true;
    }
}
