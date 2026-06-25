// Copyright (c) marcschier. All rights reserved.
// Licensed under the MIT License. See LICENSE in the project root for license information.

using System;
using System.Security.Cryptography;

namespace Dtls.Crypto;

/// <summary>
/// An <see cref="IAeadCipher"/> over the BCL <c>ChaCha20Poly1305</c> primitive,
/// used by the TLS_CHACHA20_POLY1305_SHA256 cipher suite.
/// </summary>
/// <remarks>
/// <c>ChaCha20Poly1305</c> was introduced in .NET 5 and is therefore not available
/// on <c>netstandard2.1</c>. On that target this type throws
/// <see cref="PlatformNotSupportedException"/> from its constructor; the ChaCha20-Poly1305
/// suite is consequently unsupported there.
/// </remarks>
internal sealed class ChaCha20Poly1305Cipher : IAeadCipher
{
#if NET8_0_OR_GREATER
    private readonly ChaCha20Poly1305 _chaCha;
#endif

    /// <summary>
    /// Initializes a new instance bound to <paramref name="key"/> (32 bytes).
    /// </summary>
    /// <param name="key">The AEAD key (32 bytes).</param>
    /// <exception cref="PlatformNotSupportedException">
    /// Thrown on <c>netstandard2.1</c>, where the primitive is unavailable.
    /// </exception>
    public ChaCha20Poly1305Cipher(ReadOnlySpan<byte> key)
    {
#if NET8_0_OR_GREATER
        _chaCha = new ChaCha20Poly1305(key);
#else
        _ = key;
        throw new PlatformNotSupportedException(
            "ChaCha20-Poly1305 is not available on netstandard2.1.");
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
#if NET8_0_OR_GREATER
        Span<byte> ciphertext = destination.Slice(0, plaintext.Length);
        Span<byte> tag = destination.Slice(plaintext.Length, TagLength);
        _chaCha.Encrypt(nonce, plaintext, ciphertext, tag, associatedData);
#else
        _ = nonce;
        _ = plaintext;
        _ = associatedData;
        _ = destination;
        throw new PlatformNotSupportedException(
            "ChaCha20-Poly1305 is not available on netstandard2.1.");
#endif
    }

    /// <inheritdoc />
    public bool Open(
        ReadOnlySpan<byte> nonce,
        ReadOnlySpan<byte> ciphertextAndTag,
        ReadOnlySpan<byte> associatedData,
        Span<byte> destination)
    {
#if NET8_0_OR_GREATER
        int ciphertextLength = ciphertextAndTag.Length - TagLength;
        if (ciphertextLength < 0)
        {
            return false;
        }

        ReadOnlySpan<byte> ciphertext = ciphertextAndTag.Slice(0, ciphertextLength);
        ReadOnlySpan<byte> tag = ciphertextAndTag.Slice(ciphertextLength, TagLength);

        try
        {
            _chaCha.Decrypt(nonce, ciphertext, tag, destination, associatedData);
            return true;
        }
        catch (CryptographicException)
        {
            // Authentication failure: the tag did not verify.
            return false;
        }
#else
        _ = nonce;
        _ = ciphertextAndTag;
        _ = associatedData;
        _ = destination;
        throw new PlatformNotSupportedException(
            "ChaCha20-Poly1305 is not available on netstandard2.1.");
#endif
    }

    /// <inheritdoc />
    public void Dispose()
    {
#if NET8_0_OR_GREATER
        _chaCha.Dispose();
#endif
    }
}
