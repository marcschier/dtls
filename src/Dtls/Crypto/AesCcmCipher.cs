#if NET8_0_OR_GREATER && !DTLS_NO_AESCCM
using System;
using System.Security.Cryptography;

namespace Dtls.Crypto;

/// <summary>
/// An <see cref="IAeadCipher"/> over the BCL <see cref="AesCcm"/> primitive (which in turn
/// delegates to the host OS cryptography). Used by the TLS_AES_128_CCM_SHA256 (16-byte tag)
/// and TLS_AES_128_CCM_8_SHA256 (8-byte tag) cipher suites.
/// </summary>
/// <remarks>
/// <see cref="AesCcm"/> was introduced in .NET 5 and is unavailable on
/// <c>netstandard2.1</c>; this entire type is therefore compiled only on .NET 8 or later,
/// where the AES-CCM suites are negotiable.
/// </remarks>
internal sealed class AesCcmCipher : IAeadCipher
{
    private readonly AesCcm _aesCcm;
    private readonly int _tagLength;

    /// <summary>
    /// Initializes a new instance bound to <paramref name="key"/> producing a
    /// <paramref name="tagLength"/>-byte authentication tag.
    /// </summary>
    /// <param name="key">The AEAD key (16 bytes).</param>
    /// <param name="tagLength">The authentication-tag length (8 or 16 bytes).</param>
    public AesCcmCipher(ReadOnlySpan<byte> key, int tagLength)
    {
        _aesCcm = new AesCcm(key);
        _tagLength = tagLength;
    }

    /// <inheritdoc />
    public int TagLength => _tagLength;

    /// <inheritdoc />
    public void Seal(
        ReadOnlySpan<byte> nonce,
        ReadOnlySpan<byte> plaintext,
        ReadOnlySpan<byte> associatedData,
        Span<byte> destination)
    {
        Span<byte> ciphertext = destination.Slice(0, plaintext.Length);
        Span<byte> tag = destination.Slice(plaintext.Length, _tagLength);
        _aesCcm.Encrypt(nonce, plaintext, ciphertext, tag, associatedData);
    }

    /// <inheritdoc />
    public bool Open(
        ReadOnlySpan<byte> nonce,
        ReadOnlySpan<byte> ciphertextAndTag,
        ReadOnlySpan<byte> associatedData,
        Span<byte> destination)
    {
        int ciphertextLength = ciphertextAndTag.Length - _tagLength;
        if (ciphertextLength < 0)
        {
            return false;
        }

        ReadOnlySpan<byte> ciphertext = ciphertextAndTag.Slice(0, ciphertextLength);
        ReadOnlySpan<byte> tag = ciphertextAndTag.Slice(ciphertextLength, _tagLength);

        try
        {
            _aesCcm.Decrypt(nonce, ciphertext, tag, destination, associatedData);
            return true;
        }
        catch (CryptographicException)
        {
            // Authentication failure: the tag did not verify.
            return false;
        }
    }

    /// <inheritdoc />
    public void Dispose() => _aesCcm.Dispose();
}
#endif
