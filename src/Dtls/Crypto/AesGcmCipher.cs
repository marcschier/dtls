// Copyright (c) marcschier. All rights reserved.
// Licensed under the MIT License. See LICENSE in the project root for license information.

using System;
using System.Security.Cryptography;

namespace Dtls.Crypto;

/// <summary>
/// An <see cref="IAeadCipher"/> over the BCL <c>AesGcm</c> primitive (which in turn
/// delegates to the host OS cryptography). Used by the TLS_AES_128_GCM_SHA256 and
/// TLS_AES_256_GCM_SHA384 cipher suites.
/// </summary>
/// <remarks>
/// The <c>AesGcm</c> primitive is unavailable on <c>netstandard2.0</c>; on that target this
/// type throws <see cref="PlatformNotSupportedException"/> from its constructor, so the managed
/// AEAD record layer cannot run there (the wire codecs and value types still compile and run).
/// </remarks>
internal sealed class AesGcmCipher : IAeadCipher
{
#if !NETSTANDARD2_0
    private readonly AesGcm _aesGcm;
#endif

    /// <summary>
    /// Initializes a new instance bound to <paramref name="key"/> with a 16-byte tag.
    /// </summary>
    /// <param name="key">The AEAD key (16 or 32 bytes).</param>
    /// <exception cref="PlatformNotSupportedException">
    /// Thrown on <c>netstandard2.0</c>, where the <c>AesGcm</c> primitive is unavailable.
    /// </exception>
    public AesGcmCipher(ReadOnlySpan<byte> key)
    {
#if NET8_0_OR_GREATER
        _aesGcm = new AesGcm(key, TagLength);
#elif !NETSTANDARD2_0
        _aesGcm = new AesGcm(key);
#else
        _ = key;
        throw new PlatformNotSupportedException(
            "Managed AES-GCM requires .NET 8 or later; netstandard2.0 has no AesGcm primitive.");
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
#if !NETSTANDARD2_0
        Span<byte> ciphertext = destination.Slice(0, plaintext.Length);
        Span<byte> tag = destination.Slice(plaintext.Length, TagLength);
        _aesGcm.Encrypt(nonce, plaintext, ciphertext, tag, associatedData);
#else
        _ = nonce;
        _ = plaintext;
        _ = associatedData;
        _ = destination;
        throw new PlatformNotSupportedException(
            "Managed AES-GCM requires .NET 8 or later; netstandard2.0 has no AesGcm primitive.");
#endif
    }

    /// <inheritdoc />
    public bool Open(
        ReadOnlySpan<byte> nonce,
        ReadOnlySpan<byte> ciphertextAndTag,
        ReadOnlySpan<byte> associatedData,
        Span<byte> destination)
    {
#if !NETSTANDARD2_0
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
#else
        _ = nonce;
        _ = ciphertextAndTag;
        _ = associatedData;
        _ = destination;
        throw new PlatformNotSupportedException(
            "Managed AES-GCM requires .NET 8 or later; netstandard2.0 has no AesGcm primitive.");
#endif
    }

    /// <inheritdoc />
    public void Dispose()
    {
#if !NETSTANDARD2_0
        _aesGcm.Dispose();
#endif
    }
}
