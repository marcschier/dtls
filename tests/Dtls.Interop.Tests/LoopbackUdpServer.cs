using System;
using System.Net;
using System.Net.Sockets;
using System.Threading;
using System.Threading.Tasks;
using Dtls;
using Dtls.Transport;

namespace Dtls.Interop.Tests;

/// <summary>
/// A minimal single-peer DTLS server harness over a bound loopback UDP socket. It peeks the
/// first datagram to learn the client's endpoint (without consuming it), connects the socket
/// to that peer so the rest of the handshake is a point-to-point exchange, and then drives
/// <see cref="DtlsServer.AcceptAsync"/> over a <see cref="UdpDatagramTransport"/>. This is
/// enough to interoperate with a single <c>openssl s_client</c>.
/// </summary>
internal sealed class LoopbackUdpServer : IDisposable
{
    private readonly Socket _socket;
    private int _disposed;

    private LoopbackUdpServer(Socket socket)
    {
        _socket = socket;
        Port = ((IPEndPoint)socket.LocalEndPoint!).Port;
    }

    public int Port { get; }

    public static LoopbackUdpServer Bind()
    {
        Socket socket = new(AddressFamily.InterNetwork, SocketType.Dgram, ProtocolType.Udp);
        try
        {
            socket.Bind(new IPEndPoint(IPAddress.Loopback, 0));
            return new LoopbackUdpServer(socket);
        }
        catch
        {
            socket.Dispose();
            throw;
        }
    }

    public async Task<DtlsConnection> AcceptAsync(
        DtlsServer server, CancellationToken cancellationToken)
    {
        byte[] peek = new byte[2048];
        EndPoint any = new IPEndPoint(IPAddress.Any, 0);
        SocketReceiveFromResult result = await _socket
            .ReceiveFromAsync(peek, SocketFlags.Peek, any, cancellationToken)
            .ConfigureAwait(false);

        await _socket.ConnectAsync(result.RemoteEndPoint, cancellationToken)
            .ConfigureAwait(false);

        // The listener retains ownership of the socket and disposes it; the transport only
        // borrows it for the lifetime of the connection.
#pragma warning disable CA2000
        UdpDatagramTransport transport = new(_socket, ownsSocket: false);
#pragma warning restore CA2000
        return await server.AcceptAsync(transport, cancellationToken).ConfigureAwait(false);
    }

    public void Dispose()
    {
        if (Interlocked.Exchange(ref _disposed, 1) != 0)
        {
            return;
        }

        _socket.Dispose();
    }
}
