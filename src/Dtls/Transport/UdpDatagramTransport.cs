// Copyright (c) marcschier. All rights reserved.
// Licensed under the MIT License. See LICENSE in the project root for license information.

using System;
using System.Net;
using System.Net.Sockets;
using System.Threading;
using System.Threading.Tasks;
#if NETSTANDARD2_0
using System.Buffers;
using System.Runtime.InteropServices;
#endif

namespace Dtls.Transport;

/// <summary>
/// An <see cref="IDatagramTransport"/> backed by a connected UDP <see cref="Socket"/>.
/// A connected UDP socket only exchanges datagrams with a single remote endpoint, which
/// matches the point-to-point contract of <see cref="IDatagramTransport"/> for a DTLS
/// client (or a per-peer server connection).
/// </summary>
public sealed class UdpDatagramTransport : IDatagramTransport
{
    /// <summary>The maximum UDP payload size over IPv4 (65535 minus IP and UDP headers).</summary>
    public const int MaxUdpPayload = 65507;

    private readonly Socket _socket;
    private readonly bool _ownsSocket;
    private int _disposed;

    /// <summary>
    /// Wraps an already-connected socket.
    /// </summary>
    /// <param name="connectedSocket">A UDP socket that is already connected to a peer.</param>
    /// <param name="ownsSocket">
    /// Whether disposing this transport also disposes <paramref name="connectedSocket"/>.
    /// </param>
    public UdpDatagramTransport(Socket connectedSocket, bool ownsSocket = true)
    {
        if (connectedSocket is null)
        {
            throw new ArgumentNullException(nameof(connectedSocket));
        }

        if (connectedSocket.SocketType != SocketType.Dgram)
        {
            throw new ArgumentException("A datagram socket is required.", nameof(connectedSocket));
        }

        _socket = connectedSocket;
        _ownsSocket = ownsSocket;
    }

    /// <inheritdoc />
    public int MaxDatagramSize => MaxUdpPayload;

    /// <summary>
    /// Creates a UDP socket connected to <paramref name="remoteEndPoint"/>.
    /// </summary>
    /// <param name="remoteEndPoint">The remote peer to connect to.</param>
    /// <returns>A connected transport ready to carry DTLS datagrams.</returns>
    public static UdpDatagramTransport Connect(IPEndPoint remoteEndPoint)
    {
        if (remoteEndPoint is null)
        {
            throw new ArgumentNullException(nameof(remoteEndPoint));
        }

        Socket socket = new(remoteEndPoint.AddressFamily, SocketType.Dgram, ProtocolType.Udp);
        try
        {
            socket.Connect(remoteEndPoint);
            return new UdpDatagramTransport(socket, ownsSocket: true);
        }
        catch
        {
            socket.Dispose();
            throw;
        }
    }

    /// <inheritdoc />
    public async ValueTask SendAsync(
        ReadOnlyMemory<byte> datagram,
        CancellationToken cancellationToken = default)
    {
        ThrowIfDisposed();
#if NETSTANDARD2_0
        cancellationToken.ThrowIfCancellationRequested();
        ArraySegment<byte> segment = AsArraySegment(datagram);
        await _socket.SendAsync(segment, SocketFlags.None).ConfigureAwait(false);
#else
        await _socket.SendAsync(datagram, SocketFlags.None, cancellationToken)
            .ConfigureAwait(false);
#endif
    }

    /// <inheritdoc />
    public async ValueTask<int> ReceiveAsync(
        Memory<byte> buffer,
        CancellationToken cancellationToken = default)
    {
        ThrowIfDisposed();
#if NETSTANDARD2_0
        cancellationToken.ThrowIfCancellationRequested();
        if (MemoryMarshal.TryGetArray((ReadOnlyMemory<byte>)buffer, out ArraySegment<byte> backing))
        {
            return await _socket.ReceiveAsync(backing, SocketFlags.None).ConfigureAwait(false);
        }

        byte[] rented = ArrayPool<byte>.Shared.Rent(buffer.Length);
        try
        {
            int received = await _socket
                .ReceiveAsync(new ArraySegment<byte>(rented, 0, buffer.Length), SocketFlags.None)
                .ConfigureAwait(false);
            rented.AsSpan(0, received).CopyTo(buffer.Span);
            return received;
        }
        finally
        {
            ArrayPool<byte>.Shared.Return(rented);
        }
#else
        return await _socket.ReceiveAsync(buffer, SocketFlags.None, cancellationToken)
            .ConfigureAwait(false);
#endif
    }

    /// <inheritdoc />
    public void Dispose()
    {
        if (Interlocked.Exchange(ref _disposed, 1) != 0)
        {
            return;
        }

        if (_ownsSocket)
        {
            _socket.Dispose();
        }
    }

    private void ThrowIfDisposed()
    {
        if (Volatile.Read(ref _disposed) != 0)
        {
            throw new ObjectDisposedException(nameof(UdpDatagramTransport));
        }
    }

#if NETSTANDARD2_0
    private static ArraySegment<byte> AsArraySegment(ReadOnlyMemory<byte> memory)
    {
        if (MemoryMarshal.TryGetArray(memory, out ArraySegment<byte> segment))
        {
            return segment;
        }

        return new ArraySegment<byte>(memory.ToArray());
    }
#endif
}
