using System;
using System.Security.Cryptography;

namespace Dtls.Crypto;

/// <summary>
/// Derives the record-sequence-number encryption mask defined by RFC 9147 section 4.2.3.
/// For the AES-based suites (AES-GCM and AES-CCM) the mask is a single-block AES-ECB
/// encryption of the first 16 bytes of the AEAD ciphertext under the <c>sn_key</c>.
/// </summary>
/// <remarks>
/// ChaCha20-Poly1305 sequence-number masking requires a raw ChaCha20 keystream block,
/// which the BCL does not expose; that case throws <see cref="NotSupportedException"/> and
/// is deferred (see <c>Dtls13RecordProtector</c>). The single-block ECB used here is the
/// RFC-mandated masking primitive, not a bulk encryption mode.
/// </remarks>
internal sealed class SequenceNumberEncryptor : IDisposable
{
    /// <summary>The AES block size and the length of the ciphertext mask sample.</summary>
    public const int BlockLength = 16;

    private readonly Dtls13AeadKind _aead;
    private readonly Aes? _aes;

    /// <summary>
    /// Initializes a new instance for the given cipher suite and sequence-number key.
    /// </summary>
    /// <param name="cipherSuite">The negotiated cipher suite.</param>
    /// <param name="sequenceNumberKey">The <c>sn_key</c> material.</param>
    public SequenceNumberEncryptor(
        Dtls13CipherSuite cipherSuite,
        ReadOnlySpan<byte> sequenceNumberKey)
    {
        _aead = cipherSuite.Aead;
        if (!IsAesBased(_aead))
        {
            return;
        }

        Aes aes = Aes.Create();
        try
        {
            aes.Key = sequenceNumberKey.ToArray();
#if !NET8_0_OR_GREATER
#pragma warning disable CA5358 // RFC 9147 4.2.3 mandates single-block ECB for SN masking.
            aes.Mode = CipherMode.ECB;
#pragma warning restore CA5358
            aes.Padding = PaddingMode.None;
#endif
            _aes = aes;
        }
        catch
        {
            aes.Dispose();
            throw;
        }
    }

    /// <summary>
    /// Writes the sequence-number mask into <paramref name="mask"/> by encrypting the
    /// first 16 bytes of <paramref name="ciphertextSample"/>.
    /// </summary>
    /// <param name="ciphertextSample">The AEAD ciphertext; at least 16 bytes are read.</param>
    /// <param name="mask">Receives the leading 1 or 2 bytes of the mask.</param>
    /// <exception cref="NotSupportedException">
    /// Thrown for the ChaCha20-Poly1305 suite, whose masking is not yet supported.
    /// </exception>
    public void Mask(ReadOnlySpan<byte> ciphertextSample, Span<byte> mask)
    {
        if (!IsAesBased(_aead) || _aes is null)
        {
            throw new NotSupportedException(
                "ChaCha20-Poly1305 sequence-number encryption is not yet supported.");
        }

        if (ciphertextSample.Length < BlockLength)
        {
            throw new ArgumentException(
                "The ciphertext sample must be at least 16 bytes.",
                nameof(ciphertextSample));
        }

        if (mask.Length is < 1 or > BlockLength)
        {
            throw new ArgumentException(
                "The mask length must be between 1 and 16 bytes.",
                nameof(mask));
        }

        Span<byte> block = stackalloc byte[BlockLength];
#if NET8_0_OR_GREATER
#pragma warning disable CA5358 // RFC 9147 4.2.3 mandates single-block ECB for SN masking.
        _aes.EncryptEcb(ciphertextSample.Slice(0, BlockLength), block, PaddingMode.None);
#pragma warning restore CA5358
#else
        byte[] input = ciphertextSample.Slice(0, BlockLength).ToArray();
        byte[] output = new byte[BlockLength];
        using (ICryptoTransform encryptor = _aes.CreateEncryptor())
        {
            encryptor.TransformBlock(input, 0, BlockLength, output, 0);
        }

        output.CopyTo(block);
#endif
        block.Slice(0, mask.Length).CopyTo(mask);
        CryptographicOperations.ZeroMemory(block);
    }

    /// <inheritdoc />
    public void Dispose() => _aes?.Dispose();

    private static bool IsAesBased(Dtls13AeadKind aead) =>
        aead is Dtls13AeadKind.AesGcm or Dtls13AeadKind.AesCcm;
}
