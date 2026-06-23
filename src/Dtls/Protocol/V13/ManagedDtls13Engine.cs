using System;
using System.Threading;
using System.Threading.Tasks;
using Dtls.Protocol.V13.Handshake;
using Dtls.Transport;

namespace Dtls.Protocol.V13;

/// <summary>
/// The managed DTLS 1.3 (RFC 9147) engine. It drives the handshake state machine and
/// record protection in managed code, using BCL cryptographic primitives (which delegate
/// to the host OS crypto). The current scope is the external-PSK + ECDHE (psk_dhe_ke)
/// handshake; other authentication modes and robustness features are deferred.
/// </summary>
internal sealed class ManagedDtls13Engine
{
    public static async Task<DtlsConnection> ConnectAsync(
        IDatagramTransport transport,
        DtlsClientOptions options,
        CancellationToken cancellationToken)
    {
        using CancellationTokenSource timeout = CreateTimeoutSource(
            options.HandshakeTimeout, cancellationToken);
        try
        {
            return await Dtls13ClientHandshake
                .RunAsync(transport, options, timeout.Token)
                .ConfigureAwait(false);
        }
        catch (OperationCanceledException) when (!cancellationToken.IsCancellationRequested)
        {
            throw new DtlsException("The DTLS 1.3 client handshake timed out.");
        }
    }

    public static async Task<DtlsConnection> AcceptAsync(
        IDatagramTransport transport,
        DtlsServerOptions options,
        ReadOnlyMemory<byte> initialDatagram,
        CancellationToken cancellationToken)
    {
        using CancellationTokenSource timeout = CreateTimeoutSource(
            options.HandshakeTimeout, cancellationToken);
        try
        {
            return await Dtls13ServerHandshake
                .RunAsync(transport, options, initialDatagram, timeout.Token)
                .ConfigureAwait(false);
        }
        catch (OperationCanceledException) when (!cancellationToken.IsCancellationRequested)
        {
            throw new DtlsException("The DTLS 1.3 server handshake timed out.");
        }
    }

    private static CancellationTokenSource CreateTimeoutSource(
        TimeSpan timeout,
        CancellationToken cancellationToken)
    {
        CancellationTokenSource source =
            CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        if (timeout > TimeSpan.Zero)
        {
            source.CancelAfter(timeout);
        }

        return source;
    }
}
