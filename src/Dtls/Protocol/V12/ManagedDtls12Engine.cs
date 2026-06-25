using System;
using System.Threading;
using System.Threading.Tasks;
using Dtls.Protocol.V12.Handshake;
using Dtls.Transport;

namespace Dtls.Protocol.V12;

/// <summary>
/// The managed DTLS 1.2 (RFC 6347 / RFC 5246) engine. It drives the certificate- and PSK-
/// authenticated handshake state machine and record protection in managed code using BCL
/// cryptographic primitives (which delegate to the host OS crypto). It is the universal fallback
/// used where no native OS DTLS backend is available (for example Android).
/// </summary>
internal sealed class ManagedDtls12Engine
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
            return await Dtls12ClientHandshake
                .RunAsync(transport, options, timeout.Token)
                .ConfigureAwait(false);
        }
        catch (OperationCanceledException) when (!cancellationToken.IsCancellationRequested)
        {
            throw new DtlsException("The DTLS 1.2 client handshake timed out.");
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
            return await Dtls12ServerHandshake
                .RunAsync(transport, options, initialDatagram, timeout.Token)
                .ConfigureAwait(false);
        }
        catch (OperationCanceledException) when (!cancellationToken.IsCancellationRequested)
        {
            throw new DtlsException("The DTLS 1.2 server handshake timed out.");
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
