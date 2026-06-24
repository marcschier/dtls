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

    /// <summary>
    /// Whether the server performs a stateless HelloRetryRequest cookie exchange
    /// (RFC 9147 section 5.1 / RFC 8446 section 4.2.2) before continuing the handshake. This
    /// forces the client to prove return-routability of its source address, mitigating
    /// denial-of-service amplification before the server commits handshake state. Only applies
    /// to the managed DTLS 1.3 certificate path; ignored by the native DTLS 1.0/1.2 backends
    /// and by the external-PSK path.
    /// </summary>
    public bool EnableStatelessRetry { get; init; }

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
