namespace Dtls.Protocol.V13.Handshake;

/// <summary>
/// The TLS 1.3 SignatureScheme values (RFC 8446 section 4.2.3) used for the
/// signature_algorithms extension and the CertificateVerify message. Only the schemes
/// supported by the managed certificate handshake are enumerated.
/// </summary>
internal enum SignatureScheme : ushort
{
    /// <summary>ecdsa_secp256r1_sha256 (0x0403).</summary>
    EcdsaSecp256r1Sha256 = 0x0403,

    /// <summary>ecdsa_secp384r1_sha384 (0x0503).</summary>
    EcdsaSecp384r1Sha384 = 0x0503,

    /// <summary>rsa_pss_rsae_sha256 (0x0804).</summary>
    RsaPssRsaeSha256 = 0x0804,

    /// <summary>rsa_pss_rsae_sha384 (0x0805).</summary>
    RsaPssRsaeSha384 = 0x0805,
}
