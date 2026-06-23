using System;
using System.Collections.Generic;
using System.Threading;
using System.Threading.Tasks;

namespace Dtls.Internal;

/// <summary>
/// A minimal, dependency-free asynchronous FIFO of datagrams. One producer hands whole
/// datagrams to <see cref="Write"/>; a single consumer awaits them with
/// <see cref="ReadAsync"/>. Used by the in-memory loopback transport and the server
/// demultiplexer so the library carries no external package dependency.
/// </summary>
internal sealed class AsyncDatagramChannel : IDisposable
{
    private readonly object _gate = new();
    private readonly Queue<byte[]> _queue = new();
    private readonly SemaphoreSlim _available = new(0);
    private bool _completed;
    private bool _disposed;

    /// <summary>Enqueues a copy-free datagram for the consumer.</summary>
    /// <returns><see langword="true"/> if accepted; <see langword="false"/> if completed.</returns>
    public bool Write(byte[] datagram)
    {
        if (datagram is null)
        {
            throw new ArgumentNullException(nameof(datagram));
        }

        lock (_gate)
        {
            if (_completed || _disposed)
            {
                return false;
            }

            _queue.Enqueue(datagram);
        }

        _available.Release();
        return true;
    }

    /// <summary>Awaits and dequeues the next datagram, or <see langword="null"/> at end.</summary>
    public async ValueTask<byte[]?> ReadAsync(CancellationToken cancellationToken)
    {
        await _available.WaitAsync(cancellationToken).ConfigureAwait(false);

        lock (_gate)
        {
            if (_queue.Count > 0)
            {
                return _queue.Dequeue();
            }

            // Released by Complete() with no item: signal end of stream.
            return null;
        }
    }

    /// <summary>
    /// Marks the channel complete; pending and future reads observe end of stream.
    /// </summary>
    public void Complete()
    {
        lock (_gate)
        {
            if (_completed)
            {
                return;
            }

            _completed = true;
        }

        // Wake any waiting reader so it can observe completion.
        _available.Release();
    }

    public void Dispose()
    {
        lock (_gate)
        {
            if (_disposed)
            {
                return;
            }

            _disposed = true;
            _completed = true;
            _queue.Clear();
        }

        _available.Dispose();
    }
}
