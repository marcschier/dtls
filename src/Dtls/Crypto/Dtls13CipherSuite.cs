using System;
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
}

/// <summary>
/// A descriptor for one of the three mandatory DTLS 1.3 / TLS 1.3 AEAD cipher suites
/// (RFC 9147 / RFC 8446 appendix B.4). It exposes the registered identifier, the hash
/// used by the key schedule, and the AEAD key/IV geometry needed by the record layer.
/// </summary>
internal readonly struct Dtls13CipherSuite : IEquatable<Dtls13CipherSuite>
{
    /// <summary>The fixed AEAD record-protection IV length (RFC 8446 5.3): 12 bytes.</summary>
    public const int FixedIvLength = 12;

    /// <summary>The fixed AEAD authentication-tag length for all three suites: 16 bytes.</summary>
    public const int TagLength = 16;

    private Dtls13CipherSuite(
        ushort id,
        HashAlgorithmName hashAlgorithm,
        int keyLength,
        Dtls13AeadKind aead)
    {
        Id = id;
        HashAlgorithm = hashAlgorithm;
        KeyLength = keyLength;
        IvLength = FixedIvLength;
        Aead = aead;
    }

    /// <summary>TLS_AES_128_GCM_SHA256 (0x1301).</summary>
    public static Dtls13CipherSuite Aes128GcmSha256 { get; } = new(
        0x1301,
        HashAlgorithmName.SHA256,
        16,
        Dtls13AeadKind.AesGcm);

    /// <summary>TLS_AES_256_GCM_SHA384 (0x1302).</summary>
    public static Dtls13CipherSuite Aes256GcmSha384 { get; } = new(
        0x1302,
        HashAlgorithmName.SHA384,
        32,
        Dtls13AeadKind.AesGcm);

    /// <summary>TLS_CHACHA20_POLY1305_SHA256 (0x1303).</summary>
    public static Dtls13CipherSuite ChaCha20Poly1305Sha256 { get; } = new(
        0x1303,
        HashAlgorithmName.SHA256,
        32,
        Dtls13AeadKind.ChaCha20Poly1305);

    /// <summary>The IANA-registered cipher suite identifier.</summary>
    public ushort Id { get; }

    /// <summary>The hash algorithm driving the key schedule for this suite.</summary>
    public HashAlgorithmName HashAlgorithm { get; }

    /// <summary>The AEAD key length, in bytes.</summary>
    public int KeyLength { get; }

    /// <summary>The AEAD record-protection IV length, in bytes (always 12).</summary>
    public int IvLength { get; }

    /// <summary>The AEAD construction used by this suite.</summary>
    public Dtls13AeadKind Aead { get; }

    /// <summary>
    /// Resolves a cipher suite descriptor from its registered identifier.
    /// </summary>
    /// <param name="id">The IANA cipher suite identifier.</param>
    /// <param name="suite">The resolved descriptor when supported.</param>
    /// <returns><see langword="true"/> when the suite is one of the supported three.</returns>
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
            default:
                suite = default;
                return false;
        }
    }

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
