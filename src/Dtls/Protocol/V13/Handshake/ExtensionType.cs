namespace Dtls.Protocol.V13.Handshake;

/// <summary>
/// The TLS 1.3 / DTLS 1.3 extension types relevant to a psk_dhe_ke handshake
/// (RFC 8446 section 4.2, registered values).
/// </summary>
internal enum ExtensionType : ushort
{
    /// <summary>supported_groups (10).</summary>
    SupportedGroups = 10,

    /// <summary>signature_algorithms (13).</summary>
    SignatureAlgorithms = 13,

    /// <summary>client_certificate_type (19, RFC 7250).</summary>
    ClientCertificateType = 19,

    /// <summary>server_certificate_type (20, RFC 7250).</summary>
    ServerCertificateType = 20,

    /// <summary>pre_shared_key (41).</summary>
    PreSharedKey = 41,

    /// <summary>supported_versions (43).</summary>
    SupportedVersions = 43,

    /// <summary>cookie (44).</summary>
    Cookie = 44,

    /// <summary>psk_key_exchange_modes (45).</summary>
    PskKeyExchangeModes = 45,

    /// <summary>key_share (51).</summary>
    KeyShare = 51,

    /// <summary>connection_id (54, RFC 9146).</summary>
    ConnectionId = 54,
}
