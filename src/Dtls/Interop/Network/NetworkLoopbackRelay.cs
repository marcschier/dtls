#if NET8_0_OR_GREATER
using System;
using System.Buffers;
using System.Net;
using System.Net.Sockets;
using System.Runtime.Versioning;
using System.Threading;
using System.Threading.Tasks;
using Dtls.Transport;

namespace Dtls.Interop.Network;

/// <summary>
/// Bridges Network.framework's own UDP socket to the application's datagram transport.
/// Network.framework insists on owning its transport, so the DTLS endpoint runs over a private
/// loopback socket and this relay shuttles the resulting encrypted datagrams to and from the
/// caller's transport. Two pump loops run for the lifetime of the connection: one forwards
/// datagrams produced by Network.framework (read from the loopback socket) to the transport, and
/// the other forwards datagrams received from the transport back into Network.framework.
/// </summary>
[SupportedOSPlatform("macos")]
internal sealed class NetworkLoopbackRelay : IDisposable
{
    private readonly Socket _socket;
    private readonly CancellationTokenSource _cts = new();
    private IPEndPoint _nwTarget;
    private readonly SemaphoreSlim _targetKnown = new(0, 1);
    private int _targetSignalled;
    private int _disposed;

    private NetworkLoopbackRelay(Socket socket, IPEndPoint initialTarget)
    {
        _socket = socket;
        _nwTarget = initialTarget;
    }

    /// <summary>
    /// The loopback UDP port that Network.framework should connect to (client mode).
    /// </summary>
    public int LocalPort => ((IPEndPoint)_socket.LocalEndPoint!).Port;

    /// <summary>
    /// Creates a relay bound to an ephemeral loopback port. <paramref name="initialTarget"/> is the
    /// Network.framework endpoint to send transport-sourced datagrams to before any datagram has
    /// been received from Network.framework (used in server mode to reach the listener port); pass
    /// <see langword="null"/> in client mode to learn the target from the first datagram.
    /// </summary>
    public static NetworkLoopbackRelay Create(IPEndPoint? initialTarget)
    {
        Socket socket = new(AddressFamily.InterNetwork, SocketType.Dgram, ProtocolType.Udp);
        try
        {
            socket.Bind(new IPEndPoint(IPAddress.Loopback, 0));
            NetworkLoopbackRelay relay = new(
                socket, initialTarget ?? new IPEndPoint(IPAddress.Loopback, 0));
            if (initialTarget is not null)
            {
                relay.SignalTargetKnown();
            }

            return relay;
        }
        catch
        {
            socket.Dispose();
            throw;
        }
    }

    /// <summary>
    /// Starts the two pump loops. <paramref name="initialDatagram"/>, when non-empty, is injected
    /// toward <c>initialTarget</c> first (the server's already-consumed ClientHello).
    /// </summary>
    public void Start(IDatagramTransport transport, ReadOnlyMemory<byte> initialDatagram)
    {
        _ = PumpFromNetworkAsync(transport, _cts.Token);
        _ = PumpToNetworkAsync(transport, initialDatagram, _cts.Token);
    }

    private async Task PumpFromNetworkAsync(IDatagramTransport transport, CancellationToken token)
    {
        byte[] buffer = ArrayPool<byte>.Shared.Rent(ushort.MaxValue);
        EndPoint from = new IPEndPoint(IPAddress.Loopback, 0);
        try
        {
            while (!token.IsCancellationRequested)
            {
                SocketReceiveFromResult result = await _socket
                    .ReceiveFromAsync(buffer, SocketFlags.None, from, token)
                    .ConfigureAwait(false);
                if (result.ReceivedBytes <= 0)
                {
                    continue;
                }

                _nwTarget = (IPEndPoint)result.RemoteEndPoint;
                SignalTargetKnown();

                await transport
                    .SendAsync(buffer.AsMemory(0, result.ReceivedBytes), token)
                    .ConfigureAwait(false);
            }
        }
        catch (OperationCanceledException)
        {
        }
        catch (SocketException)
        {
        }
        catch (ObjectDisposedException)
        {
        }
        finally
        {
            ArrayPool<byte>.Shared.Return(buffer);
        }
    }

    private async Task PumpToNetworkAsync(
        IDatagramTransport transport,
        ReadOnlyMemory<byte> initialDatagram,
        CancellationToken token)
    {
        byte[] buffer = ArrayPool<byte>.Shared.Rent(transport.MaxDatagramSize);
        try
        {
            await _targetKnown.WaitAsync(token).ConfigureAwait(false);

            if (!initialDatagram.IsEmpty)
            {
                await _socket
                    .SendToAsync(initialDatagram, SocketFlags.None, _nwTarget, token)
                    .ConfigureAwait(false);
            }

            while (!token.IsCancellationRequested)
            {
                int received = await transport
                    .ReceiveAsync(buffer, token)
                    .ConfigureAwait(false);
                if (received == 0)
                {
                    break;
                }

                await _socket
                    .SendToAsync(buffer.AsMemory(0, received), SocketFlags.None, _nwTarget, token)
                    .ConfigureAwait(false);
            }
        }
        catch (OperationCanceledException)
        {
        }
        catch (SocketException)
        {
        }
        catch (ObjectDisposedException)
        {
        }
        finally
        {
            ArrayPool<byte>.Shared.Return(buffer);
        }
    }

    private void SignalTargetKnown()
    {
        if (Interlocked.Exchange(ref _targetSignalled, 1) == 0)
        {
            _targetKnown.Release();
        }
    }

    /// <inheritdoc />
    public void Dispose()
    {
        if (Interlocked.Exchange(ref _disposed, 1) != 0)
        {
            return;
        }

        try
        {
            _cts.Cancel();
        }
        catch (ObjectDisposedException)
        {
        }

        _socket.Dispose();
        _cts.Dispose();
        _targetKnown.Dispose();
    }
}
#endif
