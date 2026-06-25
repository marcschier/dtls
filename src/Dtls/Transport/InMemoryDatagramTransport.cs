// Copyright (c) marcschier. All rights reserved.
// Licensed under the MIT License. See LICENSE in the project root for license information.

using System;
using System.Threading;
using System.Threading.Tasks;
using Dtls.Internal;

namespace Dtls.Transport;

/// <summary>
/// An in-process, reliable, full-duplex datagram channel between two endpoints. It is
/// primarily intended for tests, samples, and loopback scenarios where two DTLS engines
/// run in the same process. Network impairments (loss, reordering, duplication) are not
/// modelled here; wrap the endpoints in a test-side decorator to simulate those.
/// </summary>
public sealed class InMemoryDatagramTransport : IDatagramTransport
{
    private readonly AsyncDatagramChannel _inbound;
    private readonly AsyncDatagramChannel _outbound;
    private readonly int _maxDatagramSize;
    private int _disposed;

    private InMemoryDatagramTransport(
        AsyncDatagramChannel inbound,
        AsyncDatagramChannel outbound,
        int maxDatagramSize)
    {
        _inbound = inbound;
        _outbound = outbound;
        _maxDatagramSize = maxDatagramSize;
    }

    /// <inheritdoc />
    public int MaxDatagramSize => _maxDatagramSize;

    /// <summary>
    /// Creates a connected pair of endpoints. Datagrams written to one endpoint are
    /// received by the other.
    /// </summary>
    /// <param name="maxDatagramSize">The maximum datagram size for both endpoints.</param>
    /// <returns>A tuple of the two connected endpoints.</returns>
    public static (InMemoryDatagramTransport A, InMemoryDatagramTransport B) CreatePair(
        int maxDatagramSize = 65535)
    {
        if (maxDatagramSize <= 0)
        {
            throw new ArgumentOutOfRangeException(nameof(maxDatagramSize));
        }

        AsyncDatagramChannel aInbound = new();
        AsyncDatagramChannel bInbound = new();
        InMemoryDatagramTransport a = new(aInbound, bInbound, maxDatagramSize);
        InMemoryDatagramTransport b = new(bInbound, aInbound, maxDatagramSize);
        return (a, b);
    }

    /// <inheritdoc />
    public ValueTask SendAsync(
        ReadOnlyMemory<byte> datagram,
        CancellationToken cancellationToken = default)
    {
        ThrowIfDisposed();
        cancellationToken.ThrowIfCancellationRequested();

        if (datagram.Length > _maxDatagramSize)
        {
            throw new ArgumentException(
                "Datagram exceeds the maximum datagram size.",
                nameof(datagram));
        }

        // Copy because the caller may reuse its buffer once this call returns.
        _outbound.Write(datagram.ToArray());
        return default;
    }

    /// <inheritdoc />
    public async ValueTask<int> ReceiveAsync(
        Memory<byte> buffer,
        CancellationToken cancellationToken = default)
    {
        ThrowIfDisposed();

        byte[]? datagram = await _inbound.ReadAsync(cancellationToken).ConfigureAwait(false);
        if (datagram is null)
        {
            return 0;
        }

        if (datagram.Length > buffer.Length)
        {
            throw new ArgumentException(
                "The receive buffer is smaller than the incoming datagram.",
                nameof(buffer));
        }

        datagram.AsSpan().CopyTo(buffer.Span);
        return datagram.Length;
    }

    /// <inheritdoc />
    public void Dispose()
    {
        if (Interlocked.Exchange(ref _disposed, 1) != 0)
        {
            return;
        }

        _outbound.Complete();
        _inbound.Dispose();
    }

    private void ThrowIfDisposed()
    {
        if (Volatile.Read(ref _disposed) != 0)
        {
            throw new ObjectDisposedException(nameof(InMemoryDatagramTransport));
        }
    }
}
