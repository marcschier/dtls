// Copyright (c) marcschier. All rights reserved.
// Licensed under the MIT License. See LICENSE in the project root for license information.

using System;
using System.Collections.Generic;
using System.Security.Cryptography;

namespace Dtls.Crypto;

/// <summary>
/// Identifies the AEAD construction used by a DTLS 1.3 cipher suite.
/// </summary>
internal enum Dtls13AeadKind
{
    /// <summary>AES-GCM with a 128- or 256-bit key and a 16-byte authentication tag.</summary>
    AesGcm = 0,

    /// <summary>ChaCha20-Poly1305 with a 256-bit key and a 16-byte authentication tag.</summary>
    ChaCha20Poly1305 = 1,

    /// <summary>AES-CCM with a 128-bit key and an 8- or 16-byte authentication tag.</summary>
    AesCcm = 2,
}

/// <summary>
/// A descriptor for a DTLS 1.3 / TLS 1.3 AEAD cipher suite (RFC 9147 / RFC 8446
/// appendix B.4). It exposes the registered identifier, the hash used by the key schedule,
/// and the AEAD key/IV/tag geometry needed by the record layer.
/// </summary>
internal readonly struct Dtls13CipherSuite : IEquatable<Dtls13CipherSuite>
{
    /// <summary>The fixed AEAD record-protection IV length (RFC 8446 5.3): 12 bytes.</summary>
    public const int FixedIvLength = 12;

    private Dtls13CipherSuite(
        ushort id,
        HashAlgorithmName hashAlgorithm,
        int keyLength,
        int tagLength,
        Dtls13AeadKind aead)
    {
        Id = id;
        HashAlgorithm = hashAlgorithm;
        KeyLength = keyLength;
        IvLength = FixedIvLength;
        TagLength = tagLength;
        Aead = aead;
    }

    /// <summary>TLS_AES_128_GCM_SHA256 (0x1301).</summary>
    public static Dtls13CipherSuite Aes128GcmSha256 { get; } = new(
        0x1301,
        HashAlgorithmName.SHA256,
        16,
        16,
        Dtls13AeadKind.AesGcm);

    /// <summary>TLS_AES_256_GCM_SHA384 (0x1302).</summary>
    public static Dtls13CipherSuite Aes256GcmSha384 { get; } = new(
        0x1302,
        HashAlgorithmName.SHA384,
        32,
        16,
        Dtls13AeadKind.AesGcm);

    /// <summary>TLS_CHACHA20_POLY1305_SHA256 (0x1303).</summary>
    public static Dtls13CipherSuite ChaCha20Poly1305Sha256 { get; } = new(
        0x1303,
        HashAlgorithmName.SHA256,
        32,
        16,
        Dtls13AeadKind.ChaCha20Poly1305);

#if NET8_0_OR_GREATER && !DTLS_NO_AESCCM
    /// <summary>TLS_AES_128_CCM_SHA256 (0x1304). Requires .NET 8 or later.</summary>
    public static Dtls13CipherSuite Aes128CcmSha256 { get; } = new(
        0x1304,
        HashAlgorithmName.SHA256,
        16,
        16,
        Dtls13AeadKind.AesCcm);

    /// <summary>TLS_AES_128_CCM_8_SHA256 (0x1305). Requires .NET 8 or later.</summary>
    public static Dtls13CipherSuite Aes128Ccm8Sha256 { get; } = new(
        0x1305,
        HashAlgorithmName.SHA256,
        16,
        8,
        Dtls13AeadKind.AesCcm);

    /// <summary>Whether the BCL AES-CCM primitive is usable on this platform at runtime.</summary>
    private static readonly bool CcmSupported = AesCcm.IsSupported;
#endif

    /// <summary>
    /// The cipher suites supported on the current target framework, in secure default
    /// preference order. AES-CCM (0x1304, 0x1305) is only present on .NET 8 or later, where
    /// the BCL <c>AesCcm</c> primitive exists.
    /// </summary>
    public static IReadOnlyList<Dtls13CipherSuite> SupportedDefault { get; } =
        BuildSupportedDefault();

    private static Dtls13CipherSuite[] BuildSupportedDefault()
    {
#if NET8_0_OR_GREATER && !DTLS_NO_AESCCM
        if (CcmSupported)
        {
            return new[]
            {
                Aes128GcmSha256,
                Aes256GcmSha384,
                Aes128CcmSha256,
                Aes128Ccm8Sha256,
            };
        }
#endif
        return new[] { Aes128GcmSha256, Aes256GcmSha384 };
    }

    /// <summary>The IANA-registered cipher suite identifier.</summary>
    public ushort Id { get; }

    /// <summary>The hash algorithm driving the key schedule for this suite.</summary>
    public HashAlgorithmName HashAlgorithm { get; }

    /// <summary>The AEAD key length, in bytes.</summary>
    public int KeyLength { get; }

    /// <summary>The AEAD record-protection IV length, in bytes (always 12).</summary>
    public int IvLength { get; }

    /// <summary>AEAD authentication-tag length in bytes (16 for GCM/CCM, 8 for CCM-8).</summary>
    public int TagLength { get; }

    /// <summary>The AEAD construction used by this suite.</summary>
    public Dtls13AeadKind Aead { get; }

    /// <summary>
    /// Resolves a cipher suite descriptor from its registered identifier, returning only
    /// suites that are supported on the current target framework.
    /// </summary>
    /// <param name="id">The IANA cipher suite identifier.</param>
    /// <param name="suite">The resolved descriptor when supported.</param>
    /// <returns><see langword="true"/> when the suite is supported on this framework.</returns>
    public static bool TryGet(ushort id, out Dtls13CipherSuite suite)
    {
        switch (id)
        {
            case 0x1301:
                suite = Aes128GcmSha256;
                return true;
            case 0x1302:
                suite = Aes256GcmSha384;
                return true;
            case 0x1303:
                suite = ChaCha20Poly1305Sha256;
                return true;
#if NET8_0_OR_GREATER && !DTLS_NO_AESCCM
            case 0x1304:
                suite = Aes128CcmSha256;
                return CcmSupported;
            case 0x1305:
                suite = Aes128Ccm8Sha256;
                return CcmSupported;
#endif
            default:
                suite = default;
                return false;
        }
    }

    /// <summary>
    /// Indicates whether the suite identified by <paramref name="id"/> is supported and
    /// negotiable on the current target framework.
    /// </summary>
    /// <param name="id">The IANA cipher suite identifier.</param>
    /// <returns><see langword="true"/> when the suite is supported here.</returns>
    public static bool IsSupported(ushort id) => TryGet(id, out _);

    /// <inheritdoc />
    public bool Equals(Dtls13CipherSuite other) => Id == other.Id;

    /// <inheritdoc />
    public override bool Equals(object? obj) => obj is Dtls13CipherSuite other && Equals(other);

    /// <inheritdoc />
    public override int GetHashCode() => Id;

    public static bool operator ==(Dtls13CipherSuite left, Dtls13CipherSuite right) =>
        left.Equals(right);

    public static bool operator !=(Dtls13CipherSuite left, Dtls13CipherSuite right) =>
        !left.Equals(right);
}
