using System;
using System.Threading;
using System.Threading.Tasks;
using Dtls.Interop;
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

        // Offering DTLS 1.3 is driven by the managed engine; a 1.2 fallback (when the peer
        // selects <= 1.2) is restarted against the native backend by the engine.
        if (options.MaximumVersion >= DtlsProtocolVersion.Dtls13)
        {
            return ManagedDtls13Engine.ConnectAsync(transport, options, cancellationToken);
        }

        INativeDtlsBackend backend = NativeDtlsBackend.ForCurrentPlatform()
            ?? throw new PlatformNotSupportedException(
                "No native DTLS 1.0/1.2 backend is available for this operating system.");
        return backend.ConnectAsync(transport, options, cancellationToken);
    }
}
