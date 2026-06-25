// Copyright (c) marcschier. All rights reserved.
// Licensed under the MIT License. See LICENSE in the project root for license information.

using System;
using System.Collections.Generic;
using System.Security.Cryptography;

namespace Dtls.Crypto;

/// <summary>The key-exchange + authentication method of a DTLS 1.2 cipher suite.</summary>
internal enum Dtls12KeyExchange
{
    /// <summary>ECDHE with ECDSA server authentication (RFC 5289).</summary>
    EcdheEcdsa = 0,

    /// <summary>ECDHE with RSA server authentication (RFC 5289).</summary>
    EcdheRsa = 1,

    /// <summary>ECDHE with a pre-shared key (RFC 5489 / RFC 8442).</summary>
    EcdhePsk = 2,

    /// <summary>Plain pre-shared key, no (EC)DHE (RFC 5487 / RFC 6655).</summary>
    Psk = 3,
}

/// <summary>
/// A descriptor for a DTLS 1.2 / TLS 1.2 AEAD cipher suite (RFC 5289, RFC 5487/5489, RFC 6655/7251,
/// RFC 8442). It exposes the registered identifier, the key-exchange/authentication method, the PRF
/// hash, and the AEAD key/nonce/tag geometry used by the DTLS 1.2 record layer. Only AEAD suites
/// are modelled (no CBC/MAC-then-encrypt); the salt (fixed IV) is 4 bytes and the per-record
/// explicit nonce is 8 bytes (RFC 5288 / RFC 6655).
/// </summary>
internal readonly struct Dtls12CipherSuite : IEquatable<Dtls12CipherSuite>
{
    /// <summary>The fixed (implicit) IV / salt length carried in the key block: 4 bytes.</summary>
    public const int SaltLength = 4;

    /// <summary>The per-record explicit nonce length sent in the record: 8 bytes.</summary>
    public const int ExplicitNonceLength = 8;

    private Dtls12CipherSuite(
        ushort id,
        Dtls12KeyExchange keyExchange,
        HashAlgorithmName prfHash,
        int keyLength,
        int tagLength,
        Dtls13AeadKind aead)
    {
        Id = id;
        KeyExchange = keyExchange;
        PrfHash = prfHash;
        KeyLength = keyLength;
        TagLength = tagLength;
        Aead = aead;
    }

    /// <summary>The IANA-registered cipher suite identifier.</summary>
    public ushort Id { get; }

    /// <summary>The key-exchange + authentication method.</summary>
    public Dtls12KeyExchange KeyExchange { get; }

    /// <summary>The hash driving the PRF, key block, and Finished verify_data.</summary>
    public HashAlgorithmName PrfHash { get; }

    /// <summary>The AEAD key length, in bytes.</summary>
    public int KeyLength { get; }

    /// <summary>AEAD authentication-tag length, bytes (16 for GCM/CCM, 8 for CCM_8).</summary>
    public int TagLength { get; }

    /// <summary>The AEAD construction (AES-GCM or AES-CCM).</summary>
    public Dtls13AeadKind Aead { get; }

    /// <summary>Whether this suite uses a pre-shared key (PSK or ECDHE-PSK).</summary>
    public bool UsesPsk => KeyExchange is Dtls12KeyExchange.Psk or Dtls12KeyExchange.EcdhePsk;

    /// <summary>Whether this suite performs an (EC)DHE key exchange.</summary>
    public bool UsesEcdhe =>
        KeyExchange is Dtls12KeyExchange.EcdheEcdsa
            or Dtls12KeyExchange.EcdheRsa
            or Dtls12KeyExchange.EcdhePsk;

    /// <summary>Whether this suite authenticates the server with a certificate signature.</summary>
    public bool UsesCertificate =>
        KeyExchange is Dtls12KeyExchange.EcdheEcdsa or Dtls12KeyExchange.EcdheRsa;

    /// <summary>
    /// Resolves a cipher suite descriptor from its identifier, returning only AEAD suites that are
    /// supported on the current target framework (AES-CCM requires .NET 8 or later).
    /// </summary>
    public static bool TryGet(ushort id, out Dtls12CipherSuite suite)
    {
        switch (id)
        {
            case 0xC02B:
                suite = new(id, Dtls12KeyExchange.EcdheEcdsa, Sha256, 16, 16, Gcm);
                return true;
            case 0xC02C:
                suite = new(id, Dtls12KeyExchange.EcdheEcdsa, Sha384, 32, 16, Gcm);
                return true;
            case 0xC02F:
                suite = new(id, Dtls12KeyExchange.EcdheRsa, Sha256, 16, 16, Gcm);
                return true;
            case 0xC030:
                suite = new(id, Dtls12KeyExchange.EcdheRsa, Sha384, 32, 16, Gcm);
                return true;
            case 0xD001:
                suite = new(id, Dtls12KeyExchange.EcdhePsk, Sha256, 16, 16, Gcm);
                return true;
            case 0xD002:
                suite = new(id, Dtls12KeyExchange.EcdhePsk, Sha384, 32, 16, Gcm);
                return true;
            case 0x00A8:
                suite = new(id, Dtls12KeyExchange.Psk, Sha256, 16, 16, Gcm);
                return true;
            case 0x00A9:
                suite = new(id, Dtls12KeyExchange.Psk, Sha384, 32, 16, Gcm);
                return true;
#if NET8_0_OR_GREATER && !DTLS_NO_AESCCM
            case 0xC0AC:
                suite = new(id, Dtls12KeyExchange.EcdheEcdsa, Sha256, 16, 16, Ccm);
                return CcmSupported;
            case 0xC0AE:
                suite = new(id, Dtls12KeyExchange.EcdheEcdsa, Sha256, 16, 8, Ccm);
                return CcmSupported;
            case 0xC0A4:
                suite = new(id, Dtls12KeyExchange.Psk, Sha256, 16, 16, Ccm);
                return CcmSupported;
            case 0xC0A8:
                suite = new(id, Dtls12KeyExchange.Psk, Sha256, 16, 8, Ccm);
                return CcmSupported;
#endif
            default:
                suite = default;
                return false;
        }
    }

    /// <summary>Whether the suite identified by <paramref name="id"/> is supported here.</summary>
    public static bool IsSupported(ushort id) => TryGet(id, out _);

    /// <inheritdoc />
    public bool Equals(Dtls12CipherSuite other) => Id == other.Id;

    /// <inheritdoc />
    public override bool Equals(object? obj) => obj is Dtls12CipherSuite other && Equals(other);

    /// <inheritdoc />
    public override int GetHashCode() => Id;

    public static bool operator ==(Dtls12CipherSuite left, Dtls12CipherSuite right) =>
        left.Equals(right);

    public static bool operator !=(Dtls12CipherSuite left, Dtls12CipherSuite right) =>
        !left.Equals(right);

    private static HashAlgorithmName Sha256 => HashAlgorithmName.SHA256;

    private static HashAlgorithmName Sha384 => HashAlgorithmName.SHA384;

    private const Dtls13AeadKind Gcm = Dtls13AeadKind.AesGcm;

#if NET8_0_OR_GREATER && !DTLS_NO_AESCCM
    private const Dtls13AeadKind Ccm = Dtls13AeadKind.AesCcm;

    private static readonly bool CcmSupported = AesCcm.IsSupported;
#endif

    /// <summary>
    /// Builds the list of supported cipher suite identifiers for the given key-exchange methods, in
    /// secure default preference order (GCM before CCM, then by key size).
    /// </summary>
    public static IReadOnlyList<ushort> DefaultIdsFor(
        bool certificate,
        bool ecdhePsk,
        bool plainPsk)
    {
        List<ushort> ids = new();
        void Add(ushort id)
        {
            if (IsSupported(id))
            {
                ids.Add(id);
            }
        }

        if (certificate)
        {
            Add(0xC02B);
            Add(0xC02C);
            Add(0xC02F);
            Add(0xC030);
            Add(0xC0AC);
            Add(0xC0AE);
        }

        if (ecdhePsk)
        {
            Add(0xD001);
            Add(0xD002);
        }

        if (plainPsk)
        {
            Add(0x00A8);
            Add(0x00A9);
            Add(0xC0A4);
            Add(0xC0A8);
        }

        return ids;
    }
}
