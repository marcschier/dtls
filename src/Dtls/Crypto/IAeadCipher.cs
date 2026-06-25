// Copyright (c) marcschier. All rights reserved.
// Licensed under the MIT License. See LICENSE in the project root for license information.

using System;

namespace Dtls.Crypto;

/// <summary>
/// An authenticated-encryption-with-associated-data (AEAD) primitive as used by the
/// DTLS 1.3 record layer (RFC 9147 section 4). Implementations wrap a single fixed key
/// and produce/verify a 16-byte authentication tag appended to the ciphertext.
/// </summary>
internal interface IAeadCipher : IDisposable
{
    /// <summary>The AEAD authentication-tag length, in bytes.</summary>
    int TagLength { get; }

    /// <summary>
    /// Encrypts <paramref name="plaintext"/> and writes the ciphertext followed by the
    /// authentication tag into <paramref name="destination"/>.
    /// </summary>
    /// <param name="nonce">The per-record nonce (12 bytes).</param>
    /// <param name="plaintext">The plaintext to encrypt.</param>
    /// <param name="associatedData">The additional authenticated data.</param>
    /// <param name="destination">
    /// Receives <c>plaintext.Length + TagLength</c> bytes: ciphertext then tag.
    /// </param>
    void Seal(
        ReadOnlySpan<byte> nonce,
        ReadOnlySpan<byte> plaintext,
        ReadOnlySpan<byte> associatedData,
        Span<byte> destination);

    /// <summary>
    /// Verifies and decrypts <paramref name="ciphertextAndTag"/> (ciphertext followed by
    /// the 16-byte tag) into <paramref name="destination"/>.
    /// </summary>
    /// <param name="nonce">The per-record nonce (12 bytes).</param>
    /// <param name="ciphertextAndTag">The ciphertext with the appended authentication tag.</param>
    /// <param name="associatedData">The additional authenticated data.</param>
    /// <param name="destination">
    /// Receives the recovered plaintext (<c>ciphertextAndTag.Length - TagLength</c> bytes).
    /// </param>
    /// <returns>
    /// <see langword="true"/> when authentication succeeds; <see langword="false"/> when
    /// the tag does not verify (the contents of <paramref name="destination"/> must then
    /// be ignored).
    /// </returns>
    bool Open(
        ReadOnlySpan<byte> nonce,
        ReadOnlySpan<byte> ciphertextAndTag,
        ReadOnlySpan<byte> associatedData,
        Span<byte> destination);
}
