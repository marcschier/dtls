using System;
using System.Buffers;
using System.Threading;
using System.Threading.Tasks;
using Dtls.Interop;
using Dtls.Protocol.V13;
using Dtls.Routing;
using Dtls.Transport;

namespace Dtls;

/// <summary>
/// Accepts inbound (server) DTLS connections. The first datagram of each connection is
/// inspected and routed to the managed DTLS 1.3 engine or the native DTLS 1.0/1.2 backend
/// based on the offered version (the hybrid server design).
/// </summary>
public sealed class DtlsServer
{
    private readonly DtlsServerOptions _options;

    /// <summary>Initializes a new server with the given configuration.</summary>
    /// <param name="options">The server configuration.</param>
    public DtlsServer(DtlsServerOptions options)
    {
        if (options is null)
        {
            throw new ArgumentNullException(nameof(options));
        }

        options.Validate();
        _options = options;
    }

    /// <summary>
    /// Performs a server DTLS handshake over <paramref name="transport"/>, which carries a
    /// single client's datagrams.
    /// </summary>
    /// <param name="transport">The per-peer datagram transport.</param>
    /// <param name="cancellationToken">A token to cancel the handshake.</param>
    /// <returns>An established <see cref="DtlsConnection"/>.</returns>
    public async Task<DtlsConnection> AcceptAsync(
        IDatagramTransport transport,
        CancellationToken cancellationToken = default)
    {
        if (transport is null)
        {
            throw new ArgumentNullException(nameof(transport));
        }

        byte[] buffer = ArrayPool<byte>.Shared.Rent(transport.MaxDatagramSize);
        try
        {
            int received = await transport.ReceiveAsync(buffer, cancellationToken)
                .ConfigureAwait(false);
            DtlsRoute route = ClientHelloVersionPeek.Inspect(buffer.AsSpan(0, received));

            if (route == DtlsRoute.Managed13)
            {
                return await ManagedDtls13Engine
                    .AcceptAsync(
                        transport,
                        _options,
                        buffer.AsSpan(0, received).ToArray(),
                        cancellationToken)
                    .ConfigureAwait(false);
            }

            if (route == DtlsRoute.NativeLegacy)
            {
                return await AcceptNativeAsync(
                        transport,
                        buffer.AsSpan(0, received).ToArray(),
                        cancellationToken)
                    .ConfigureAwait(false);
            }

            throw new DtlsException(
                "Unable to determine the DTLS version from the initial ClientHello.");
        }
        finally
        {
            ArrayPool<byte>.Shared.Return(buffer);
        }
    }

    private Task<DtlsConnection> AcceptNativeAsync(
        IDatagramTransport transport,
        ReadOnlyMemory<byte> initialDatagram,
        CancellationToken cancellationToken)
    {
        INativeDtlsBackend backend = NativeDtlsBackend.ForCurrentPlatform()
            ?? throw new PlatformNotSupportedException(
                "No native DTLS 1.0/1.2 backend is available for this operating system.");
        return backend.AcceptAsync(transport, _options, initialDatagram, cancellationToken);
    }
}
