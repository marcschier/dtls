namespace Dtls;

/// <summary>
/// Identifies a DTLS protocol version.
/// </summary>
/// <remarks>
/// These are logical identifiers. The on-the-wire <c>ProtocolVersion</c> encoding
/// (the one's-complement scheme defined by the DTLS RFCs) is handled by the record
/// codec, not by these values.
/// </remarks>
public enum DtlsProtocolVersion
{
    /// <summary>
    /// No version specified. This is the default value and is never negotiated.
    /// </summary>
    None = 0,

    /// <summary>
    /// DTLS 1.0 (RFC 4347). Deprecated and insecure (RFC 8996); disabled by default.
    /// Handled by the host operating system's native DTLS stack.
    /// </summary>
    Dtls10 = 1,

    /// <summary>
    /// DTLS 1.2 (RFC 6347). Handled by the host operating system's native DTLS stack.
    /// </summary>
    Dtls12 = 2,

    /// <summary>
    /// DTLS 1.3 (RFC 9147). Handled by the managed implementation.
    /// </summary>
    Dtls13 = 3,
}
