namespace Dtls.Protocol.V13.Handshake;

/// <summary>
/// The TLS 1.3 named groups (RFC 8446 section 4.2.7) used for (EC)DHE key exchange. Only
/// the NIST P-curves and X25519 are listed; the managed implementation supports the
/// P-curves (see <see cref="Dtls.Crypto.EcdheKeyExchange"/>).
/// </summary>
internal enum NamedGroup : ushort
{
    /// <summary>secp256r1 / NIST P-256 (0x0017).</summary>
    Secp256r1 = 0x0017,

    /// <summary>secp384r1 / NIST P-384 (0x0018).</summary>
    Secp384r1 = 0x0018,

    /// <summary>secp521r1 / NIST P-521 (0x0019).</summary>
    Secp521r1 = 0x0019,

    /// <summary>x25519 (0x001D).</summary>
    X25519 = 0x001D,
}

/// <summary>
/// The TLS 1.3 PSK key-exchange modes (RFC 8446 section 4.2.9).
/// </summary>
internal enum PskKeyExchangeMode : byte
{
    /// <summary>psk_ke (0): PSK-only key establishment.</summary>
    PskKe = 0,

    /// <summary>psk_dhe_ke (1): PSK with (EC)DHE key establishment.</summary>
    PskDheKe = 1,
}
