using System;
using System.Buffers;
using System.Security.Cryptography;
using Dtls.Crypto;
using Dtls.Internal;

namespace Dtls.Protocol.V13;

/// <summary>
/// Protects and unprotects DTLS 1.3 records (RFC 9147 sections 4 and 5). It builds and
/// parses the unified record header, applies AEAD record protection with the per-record
/// nonce, and performs RFC 9147 section 4.2.3 sequence-number encryption.
/// </summary>
/// <remarks>
/// <para>
/// The AEAD additional data is the unified header exactly as transmitted but with the
/// sequence number in its pre-encryption (plaintext) form, per RFC 9147 section 5.2.
/// </para>
/// <para>
/// Sequence-number encryption is implemented for the AES-GCM suites only. The
/// ChaCha20-Poly1305 suite requires a raw ChaCha20 keystream block that the BCL does not
/// expose, so this protector throws <see cref="NotSupportedException"/> for that suite;
/// support is deferred.
/// </para>
/// <para>This type takes ownership of the supplied <see cref="Dtls13RecordKeys"/>.</para>
/// </remarks>
internal sealed class Dtls13RecordProtector : IDisposable
{
    private const int NonceLength = Dtls13CipherSuite.FixedIvLength;

    private readonly Dtls13RecordKeys _keys;
    private readonly IAeadCipher _aead;
    private readonly SequenceNumberEncryptor _sequenceNumberEncryptor;
    private readonly AntiReplayWindow _replayWindow;
    private readonly int _connectionIdLength;
    private readonly int _tagLength;

    private ulong _highestReceivedSequence;
    private bool _hasReceived;
    private bool _disposed;

    /// <summary>
    /// Initializes a new protector over the supplied record keys.
    /// </summary>
    /// <param name="keys">The per-record key material (ownership is transferred).</param>
    /// <param name="connectionIdLength">
    /// The Connection ID length used by this association when a CID is present (0 when
    /// CIDs are not used).
    /// </param>
    /// <param name="replayWindow">
    /// An optional anti-replay window; a fresh one is created when not supplied.
    /// </param>
    public Dtls13RecordProtector(
        Dtls13RecordKeys keys,
        int connectionIdLength = 0,
        AntiReplayWindow? replayWindow = null)
    {
        if (keys is null)
        {
            throw new ArgumentNullException(nameof(keys));
        }

        if (connectionIdLength < 0)
        {
            throw new ArgumentOutOfRangeException(nameof(connectionIdLength));
        }

        _keys = keys;
        _aead = keys.CreateAead();
        _sequenceNumberEncryptor = new SequenceNumberEncryptor(
            keys.CipherSuite,
            keys.SequenceNumberKey);
        _replayWindow = replayWindow ?? new AntiReplayWindow();
        _connectionIdLength = connectionIdLength;
        _tagLength = _aead.TagLength;
    }

    /// <summary>The cipher suite this protector encrypts with.</summary>
    public Dtls13CipherSuite CipherSuite => _keys.CipherSuite;

    /// <summary>
    /// Returns the number of bytes <see cref="Seal"/> writes for the given plaintext.
    /// </summary>
    /// <param name="connectionIdLength">The Connection ID length (0 when absent).</param>
    /// <param name="sequenceNumber">The record sequence number.</param>
    /// <param name="plaintextLength">The plaintext length.</param>
    /// <returns>The total sealed record length in bytes.</returns>
    public int GetSealedLength(
        int connectionIdLength,
        ulong sequenceNumber,
        int plaintextLength)
    {
        bool sixteenBit = sequenceNumber > byte.MaxValue;
        int headerLength = Dtls13RecordHeader.ComputeLength(
            connectionIdLength,
            sixteenBit,
            lengthPresent: true);
        return headerLength + plaintextLength + 1 + _tagLength;
    }

    /// <summary>
    /// Seals one record: builds the unified header, AEAD-encrypts the inner plaintext, and
    /// encrypts the sequence number.
    /// </summary>
    /// <param name="epoch">The record epoch (only its low two bits are encoded).</param>
    /// <param name="sequenceNumber">The record sequence number.</param>
    /// <param name="contentType">The TLS content type of the inner plaintext.</param>
    /// <param name="plaintext">The record payload.</param>
    /// <param name="connectionId">The Connection ID, or empty when absent.</param>
    /// <param name="destination">The buffer receiving the sealed record.</param>
    /// <returns>The number of bytes written to <paramref name="destination"/>.</returns>
    public int Seal(
        ushort epoch,
        ulong sequenceNumber,
        byte contentType,
        ReadOnlySpan<byte> plaintext,
        ReadOnlySpan<byte> connectionId,
        Span<byte> destination)
    {
        ThrowIfDisposed();

        bool sixteenBit = sequenceNumber > byte.MaxValue;
        int seqLength = sixteenBit ? 2 : 1;
        ushort encodedSeq = (ushort)(sixteenBit
            ? (sequenceNumber & 0xFFFF)
            : (sequenceNumber & 0xFF));

        int innerLength = plaintext.Length + 1;
        int encryptedLength = innerLength + _tagLength;
        int headerLength = Dtls13RecordHeader.ComputeLength(
            connectionId.Length,
            sixteenBit,
            lengthPresent: true);
        int total = headerLength + encryptedLength;

        if (encryptedLength > ushort.MaxValue)
        {
            throw new ArgumentException(
                "The record is too large for an explicit length field.",
                nameof(plaintext));
        }

        if (destination.Length < total)
        {
            throw new ArgumentException(
                "Destination is too small for the sealed record.",
                nameof(destination));
        }

        // Header with the plaintext sequence number (this is the AEAD additional data).
        Dtls13RecordHeader.Write(
            destination,
            epoch,
            connectionId,
            encodedSeq,
            sixteenBit,
            lengthPresent: true,
            (ushort)encryptedLength);

        Span<byte> header = destination.Slice(0, headerLength);
        Span<byte> encryptedRecord = destination.Slice(headerLength, encryptedLength);

        byte[] inner = ArrayPool<byte>.Shared.Rent(innerLength);
        try
        {
            plaintext.CopyTo(inner);
            inner[plaintext.Length] = contentType;

            Span<byte> nonce = stackalloc byte[NonceLength];
            _keys.ComputeNonce(sequenceNumber, nonce);

            _aead.Seal(nonce, inner.AsSpan(0, innerLength), header, encryptedRecord);
            CryptographicOperations.ZeroMemory(nonce);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(inner.AsSpan(0, innerLength));
            ArrayPool<byte>.Shared.Return(inner);
        }

        // Encrypt the on-wire sequence number (RFC 9147 4.2.3).
        Span<byte> mask = stackalloc byte[seqLength];
        _sequenceNumberEncryptor.Mask(encryptedRecord, mask);

        int seqOffset = 1 + connectionId.Length;
        for (int i = 0; i < seqLength; i++)
        {
            destination[seqOffset + i] ^= mask[i];
        }

        return total;
    }

    /// <summary>
    /// Attempts to unprotect one record: parses the unified header, decrypts the sequence
    /// number, verifies and decrypts the AEAD payload, and applies anti-replay.
    /// </summary>
    /// <param name="record">The received record bytes.</param>
    /// <param name="contentType">The recovered inner content type on success.</param>
    /// <param name="plaintext">The recovered plaintext on success.</param>
    /// <param name="sequenceNumber">The reconstructed full sequence number on success.</param>
    /// <returns>
    /// <see langword="true"/> when the record authenticates and is not a replay.
    /// </returns>
    public bool TryOpen(
        ReadOnlySpan<byte> record,
        out byte contentType,
        out byte[] plaintext,
        out ulong sequenceNumber)
    {
        ThrowIfDisposed();

        contentType = 0;
        plaintext = Array.Empty<byte>();
        sequenceNumber = 0;

        if (!Dtls13RecordHeader.TryParse(record, _connectionIdLength, out var header))
        {
            return false;
        }

        int encryptedLength = header.EncryptedRecordLength;
        if (encryptedLength < SequenceNumberEncryptor.BlockLength
            || encryptedLength < _tagLength + 1)
        {
            return false;
        }

        ReadOnlySpan<byte> encryptedRecord = record.Slice(
            header.EncryptedRecordOffset,
            encryptedLength);

        // Decrypt the sequence number (RFC 9147 4.2.3).
        Span<byte> mask = stackalloc byte[header.SequenceNumberLength];
        _sequenceNumberEncryptor.Mask(encryptedRecord, mask);

        ulong partialSequence;
        if (header.SixteenBitSequenceNumber)
        {
            int value = (header.EncodedSequenceNumber ^ ((mask[0] << 8) | mask[1])) & 0xFFFF;
            partialSequence = (ulong)value;
        }
        else
        {
            partialSequence = (ulong)(header.EncodedSequenceNumber ^ mask[0]) & 0xFF;
        }

        ulong fullSequence = ReconstructSequenceNumber(
            partialSequence,
            header.SixteenBitSequenceNumber ? 16 : 8);

        if (!_replayWindow.CanAccept(fullSequence))
        {
            return false;
        }

        // Rebuild the additional data: the header with the plaintext sequence number.
        int headerLength = header.HeaderLength;
        byte[] aad = ArrayPool<byte>.Shared.Rent(headerLength);
        byte[] decrypted = ArrayPool<byte>.Shared.Rent(encryptedLength - _tagLength);
        try
        {
            record.Slice(0, headerLength).CopyTo(aad);
            if (header.SixteenBitSequenceNumber)
            {
                aad[header.SequenceNumberOffset] = (byte)(partialSequence >> 8);
                aad[header.SequenceNumberOffset + 1] = (byte)partialSequence;
            }
            else
            {
                aad[header.SequenceNumberOffset] = (byte)partialSequence;
            }

            int plaintextLength = encryptedLength - _tagLength;
            Span<byte> nonce = stackalloc byte[NonceLength];
            _keys.ComputeNonce(fullSequence, nonce);

            bool opened = _aead.Open(
                nonce,
                encryptedRecord,
                aad.AsSpan(0, headerLength),
                decrypted.AsSpan(0, plaintextLength));
            CryptographicOperations.ZeroMemory(nonce);

            if (!opened)
            {
                return false;
            }

            // Strip the zero padding, then the trailing content-type byte.
            int end = plaintextLength - 1;
            while (end >= 0 && decrypted[end] == 0)
            {
                end--;
            }

            if (end < 0)
            {
                return false;
            }

            contentType = decrypted[end];
            plaintext = decrypted.AsSpan(0, end).ToArray();

            _replayWindow.MarkAccepted(fullSequence);
            if (!_hasReceived || fullSequence > _highestReceivedSequence)
            {
                _highestReceivedSequence = fullSequence;
                _hasReceived = true;
            }

            sequenceNumber = fullSequence;
            return true;
        }
        finally
        {
            CryptographicOperations.ZeroMemory(decrypted.AsSpan(0, encryptedLength - _tagLength));
            ArrayPool<byte>.Shared.Return(decrypted);
            ArrayPool<byte>.Shared.Return(aad);
        }
    }

    private ulong ReconstructSequenceNumber(ulong partial, int bits)
    {
        if (!_hasReceived)
        {
            return partial;
        }

        ulong window = 1UL << bits;
        ulong mask = window - 1;
        ulong masked = partial & mask;
        ulong baseValue = _highestReceivedSequence & ~mask;
        ulong candidate = baseValue | masked;

        ulong best = candidate;
        ulong bestDistance = Distance(candidate, _highestReceivedSequence);

        if (candidate >= window)
        {
            ulong lower = candidate - window;
            ulong distance = Distance(lower, _highestReceivedSequence);
            if (distance < bestDistance)
            {
                best = lower;
                bestDistance = distance;
            }
        }

        if (candidate <= ulong.MaxValue - window)
        {
            ulong upper = candidate + window;
            ulong distance = Distance(upper, _highestReceivedSequence);
            if (distance < bestDistance)
            {
                best = upper;
            }
        }

        return best;
    }

    private static ulong Distance(ulong a, ulong b) => a >= b ? a - b : b - a;

    private void ThrowIfDisposed()
    {
        if (_disposed)
        {
            throw new ObjectDisposedException(nameof(Dtls13RecordProtector));
        }
    }

    /// <inheritdoc />
    public void Dispose()
    {
        if (_disposed)
        {
            return;
        }

        _aead.Dispose();
        _sequenceNumberEncryptor.Dispose();
        _keys.Dispose();
        _disposed = true;
    }
}
