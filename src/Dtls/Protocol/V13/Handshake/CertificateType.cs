namespace Dtls.Protocol.V13.Handshake;

/// <summary>
/// The certificate type values used by the client_certificate_type and
/// server_certificate_type extensions (RFC 7250). Only the types relevant to the managed
/// handshake are enumerated.
/// </summary>
internal enum CertificateType : byte
{
    /// <summary>X.509 certificate (0).</summary>
    X509 = 0,

    /// <summary>Raw public key, a DER-encoded SubjectPublicKeyInfo (2).</summary>
    RawPublicKey = 2,
}
