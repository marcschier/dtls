// Copyright (c) marcschier. All rights reserved.
// Licensed under the MIT License. See LICENSE in the project root for license information.

using System;
using System.Security.Cryptography;

namespace Dtls.Crypto;

/// <summary>
/// An <see cref="IAeadCipher"/> over the BCL <see cref="AesGcm"/> primitive (which in turn
/// delegates to the host OS cryptography). Used by the TLS_AES_128_GCM_SHA256 and
/// TLS_AES_256_GCM_SHA384 cipher suites. Available on every target framework.
/// </summary>
internal sealed class AesGcmCipher : IAeadCipher
{
    private readonly AesGcm _aesGcm;

    /// <summary>
    /// Initializes a new instance bound to <paramref name="key"/> with a 16-byte tag.
    /// </summary>
    /// <param name="key">The AEAD key (16 or 32 bytes).</param>
    public AesGcmCipher(ReadOnlySpan<byte> key)
    {
#if NET8_0_OR_GREATER
        _aesGcm = new AesGcm(key, TagLength);
#else
        _aesGcm = new AesGcm(key);
#endif
    }

    /// <inheritdoc />
    public int TagLength => 16;

    /// <inheritdoc />
    public void Seal(
        ReadOnlySpan<byte> nonce,
        ReadOnlySpan<byte> plaintext,
        ReadOnlySpan<byte> associatedData,
        Span<byte> destination)
    {
        Span<byte> ciphertext = destination.Slice(0, plaintext.Length);
        Span<byte> tag = destination.Slice(plaintext.Length, TagLength);
        _aesGcm.Encrypt(nonce, plaintext, ciphertext, tag, associatedData);
    }

    /// <inheritdoc />
    public bool Open(
        ReadOnlySpan<byte> nonce,
        ReadOnlySpan<byte> ciphertextAndTag,
        ReadOnlySpan<byte> associatedData,
        Span<byte> destination)
    {
        int ciphertextLength = ciphertextAndTag.Length - TagLength;
        if (ciphertextLength < 0)
        {
            return false;
        }

        ReadOnlySpan<byte> ciphertext = ciphertextAndTag.Slice(0, ciphertextLength);
        ReadOnlySpan<byte> tag = ciphertextAndTag.Slice(ciphertextLength, TagLength);

        try
        {
            _aesGcm.Decrypt(nonce, ciphertext, tag, destination, associatedData);
            return true;
        }
        catch (CryptographicException)
        {
            // Authentication failure: the tag did not verify.
            return false;
        }
    }

    /// <inheritdoc />
    public void Dispose() => _aesGcm.Dispose();
}
