using System;
using System.Collections.Generic;
using Dtls.Internal;

namespace Dtls;

/// <summary>
/// Settings shared by DTLS client and server endpoints: the acceptable protocol version
/// range and the anti-denial-of-service limits applied during the handshake.
/// </summary>
public abstract class DtlsOptions
{
    /// <summary>
    /// The lowest acceptable protocol version.
    /// Defaults to <see cref="DtlsProtocolVersion.Dtls12"/>.
    /// </summary>
    public DtlsProtocolVersion MinimumVersion { get; init; } = DtlsProtocolVersion.Dtls12;

    /// <summary>
    /// The highest acceptable protocol version.
    /// Defaults to <see cref="DtlsProtocolVersion.Dtls13"/>.
    /// </summary>
    public DtlsProtocolVersion MaximumVersion { get; init; } = DtlsProtocolVersion.Dtls13;

    /// <summary>
    /// Explicitly opts in to deprecated, insecure DTLS 1.0 (RFC 8996). Required when
    /// <see cref="MinimumVersion"/> is <see cref="DtlsProtocolVersion.Dtls10"/>.
    /// </summary>
    public bool AllowDeprecatedDtls10 { get; init; }

    /// <summary>
    /// The maximum reassembled handshake message size, in bytes. Bounds memory used while
    /// reassembling fragmented flights. Defaults to 64 KiB.
    /// </summary>
    public int MaxHandshakeMessageSize { get; init; } = 64 * 1024;

    /// <summary>The overall handshake timeout. Defaults to 30 seconds.</summary>
    public TimeSpan HandshakeTimeout { get; init; } = TimeSpan.FromSeconds(30);

    /// <summary>
    /// The DTLS 1.3 AEAD cipher suites to negotiate, in preference order. An empty list
    /// (the default) negotiates all suites supported on the current target framework, in a
    /// secure default order. The AES-CCM suites
    /// (<see cref="DtlsCipherSuite.Aes128CcmSha256"/>,
    /// <see cref="DtlsCipherSuite.Aes128Ccm8Sha256"/>) are only negotiable on .NET 8 or
    /// later; entries unsupported on the current framework are ignored.
    /// </summary>
    public IReadOnlyList<DtlsCipherSuite> CipherSuites { get; init; } = new List<DtlsCipherSuite>();

    /// <summary>Validates the option values and throws on inconsistencies.</summary>
    /// <exception cref="DtlsException">The options are inconsistent or unsafe.</exception>
    public virtual void Validate()
    {
        if (MinimumVersion == DtlsProtocolVersion.None
            || MaximumVersion == DtlsProtocolVersion.None)
        {
            throw new DtlsException("Minimum and maximum versions must be specified.");
        }

        if (MinimumVersion > MaximumVersion)
        {
            throw new DtlsException("MinimumVersion must not be greater than MaximumVersion.");
        }

        if (MinimumVersion == DtlsProtocolVersion.Dtls10 && !AllowDeprecatedDtls10)
        {
            throw new DtlsException(
                "DTLS 1.0 is deprecated and insecure; set AllowDeprecatedDtls10 to enable it.");
        }

        if (MaxHandshakeMessageSize <= 0)
        {
            throw new DtlsException("MaxHandshakeMessageSize must be positive.");
        }

        if (HandshakeTimeout <= TimeSpan.Zero)
        {
            throw new DtlsException("HandshakeTimeout must be positive.");
        }

        if (CipherSuites.Count > 0 && !CipherSuitePolicy.HasSupportedEntry(CipherSuites))
        {
            throw new DtlsException(
                "None of the configured CipherSuites are supported on this target framework "
                + "(the AES-CCM suites require .NET 8 or later).");
        }
    }
}
