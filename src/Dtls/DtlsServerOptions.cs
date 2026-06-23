using System.Security.Cryptography.X509Certificates;

namespace Dtls;

/// <summary>
/// Configuration for a DTLS server endpoint.
/// </summary>
public sealed class DtlsServerOptions : DtlsOptions
{
    /// <summary>
    /// The server's certificate (with private key) used for certificate-based
    /// authentication. May be <see langword="null"/> for PSK-only servers.
    /// </summary>
    public X509Certificate2? ServerCertificate { get; init; }

    /// <summary>
    /// An optional callback resolving a pre-shared key for a client identity. When
    /// <see langword="null"/>, PSK authentication is not accepted.
    /// </summary>
    public DtlsPskServerCallback? PskCallback { get; init; }

    /// <summary>
    /// Whether the server requires the client to authenticate with a certificate.
    /// </summary>
    public bool RequireClientCertificate { get; init; }

    /// <summary>
    /// An optional callback to validate a client certificate when one is provided.
    /// </summary>
    public DtlsRemoteCertificateValidation? ClientCertificateValidation { get; init; }

    /// <summary>Whether to accept raw public keys (RFC 7250) from clients.</summary>
    public bool AllowRawPublicKeys { get; init; }

    /// <summary>An optional validator for a client raw public key (RFC 7250).</summary>
    public DtlsRawPublicKeyValidation? RawPublicKeyValidation { get; init; }

    /// <inheritdoc />
    public override void Validate()
    {
        base.Validate();

        bool hasCredential = ServerCertificate is not null
            || PskCallback is not null
            || AllowRawPublicKeys;

        if (!hasCredential)
        {
            throw new DtlsException(
                "A server must configure at least one credential "
                + "(ServerCertificate, PskCallback, or raw public keys).");
        }
    }
}
