// Copyright (c) marcschier. All rights reserved.
// Licensed under the MIT License. See LICENSE in the project root for license information.

using System.Security.Cryptography.X509Certificates;

namespace Dtls;

/// <summary>
/// Configuration for a DTLS client endpoint.
/// </summary>
public sealed class DtlsClientOptions : DtlsOptions
{
    /// <summary>
    /// The expected server host name, used for the server_name extension and for the
    /// default certificate identity check.
    /// </summary>
    public string? TargetHost { get; init; }

    /// <summary>
    /// Client certificates offered if the server requests client authentication.
    /// </summary>
    public X509Certificate2Collection ClientCertificates { get; } = new();

    /// <summary>
    /// An optional callback to validate the server certificate. When <see langword="null"/>,
    /// the platform's default chain and identity validation is used.
    /// </summary>
    public DtlsRemoteCertificateValidation? RemoteCertificateValidation { get; init; }

    /// <summary>
    /// An optional callback supplying a pre-shared key for PSK cipher suites. When
    /// <see langword="null"/>, PSK authentication is not offered.
    /// </summary>
    public DtlsPskClientCallback? PskCallback { get; init; }

    /// <summary>Whether to offer raw public keys (RFC 7250) instead of certificates.</summary>
    public bool AllowRawPublicKeys { get; init; }

    /// <summary>An optional validator for a server raw public key (RFC 7250).</summary>
    public DtlsRawPublicKeyValidation? RawPublicKeyValidation { get; init; }
}
