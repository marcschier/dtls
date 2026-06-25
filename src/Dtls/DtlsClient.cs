// Copyright (c) marcschier. All rights reserved.
// Licensed under the MIT License. See LICENSE in the project root for license information.

using System;
using System.Threading;
using System.Threading.Tasks;
using Dtls.Interop;
using Dtls.Protocol.V12;
using Dtls.Protocol.V13;
using Dtls.Transport;

namespace Dtls;

/// <summary>
/// Establishes outbound (client) DTLS connections. Based on the configured version range,
/// the request is routed either to the managed DTLS 1.3 engine or to the native operating
/// system DTLS 1.0/1.2 backend.
/// </summary>
public static class DtlsClient
{
    /// <summary>
    /// Performs a DTLS handshake as the client over <paramref name="transport"/>.
    /// </summary>
    /// <param name="transport">The connected datagram transport to the server.</param>
    /// <param name="options">The client configuration.</param>
    /// <param name="cancellationToken">A token to cancel the handshake.</param>
    /// <returns>An established <see cref="DtlsConnection"/>.</returns>
    public static Task<DtlsConnection> ConnectAsync(
        IDatagramTransport transport,
        DtlsClientOptions options,
        CancellationToken cancellationToken = default)
    {
        if (transport is null)
        {
            throw new ArgumentNullException(nameof(transport));
        }

        if (options is null)
        {
            throw new ArgumentNullException(nameof(options));
        }

        options.Validate();

        // Offering DTLS 1.3 is driven by the managed engine. When the version range also permits
        // DTLS 1.2 (and no PSK is configured), the certificate ClientHello offers both versions and
        // the engine falls back to the managed DTLS 1.2 engine if the peer selects 1.2.
        if (options.MaximumVersion >= DtlsProtocolVersion.Dtls13)
        {
            bool allowDtls12Fallback =
                options.MinimumVersion <= DtlsProtocolVersion.Dtls12
                && options.PskCallback is null;
            return ManagedDtls13Engine.ConnectAsync(
                transport, options, cancellationToken, allowDtls12Fallback);
        }

        // DTLS 1.0/1.2 prefer the native OS backend; where none exists (for example Android) the
        // managed DTLS 1.2 engine is the universal fallback.
        INativeDtlsBackend? backend = NativeDtlsBackend.ForCurrentPlatform();
        if (backend is not null)
        {
            return backend.ConnectAsync(transport, options, cancellationToken);
        }

        if (options.MinimumVersion <= DtlsProtocolVersion.Dtls12)
        {
            return ManagedDtls12Engine.ConnectAsync(transport, options, cancellationToken);
        }

        throw new PlatformNotSupportedException(
            "No native DTLS 1.0/1.2 backend is available for this operating system.");
    }
}
