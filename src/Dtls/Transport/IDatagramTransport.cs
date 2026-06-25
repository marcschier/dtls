// Copyright (c) marcschier. All rights reserved.
// Licensed under the MIT License. See LICENSE in the project root for license information.

using System;
using System.Threading;
using System.Threading.Tasks;

namespace Dtls.Transport;

/// <summary>
/// A connected, point-to-point datagram channel that carries opaque packets to and
/// from a single remote peer. DTLS engines read and write whole datagrams through this
/// abstraction, which keeps the protocol independent of any particular transport
/// (UDP, in-memory loopback, SCTP, a test harness, and so on).
/// </summary>
/// <remarks>
/// Implementations preserve datagram boundaries: each <see cref="ReceiveAsync"/> call
/// returns exactly one datagram, and each <see cref="SendAsync"/> call transmits exactly
/// one. Datagrams may be lost, duplicated, or reordered by the underlying network, which
/// is expected and handled by the DTLS record and handshake layers.
/// </remarks>
public interface IDatagramTransport : IDisposable
{
    /// <summary>
    /// The largest datagram, in bytes, that can be sent or received in a single operation.
    /// </summary>
    int MaxDatagramSize { get; }

    /// <summary>
    /// Sends a single datagram to the remote peer.
    /// </summary>
    /// <param name="datagram">The datagram payload to send.</param>
    /// <param name="cancellationToken">A token to cancel the send.</param>
    /// <returns>A task that completes when the datagram has been handed to the transport.</returns>
    ValueTask SendAsync(
        ReadOnlyMemory<byte> datagram,
        CancellationToken cancellationToken = default);

    /// <summary>
    /// Receives the next datagram from the remote peer into <paramref name="buffer"/>.
    /// </summary>
    /// <param name="buffer">
    /// The destination buffer. It must be at least <see cref="MaxDatagramSize"/> bytes to
    /// guarantee that any datagram fits.
    /// </param>
    /// <param name="cancellationToken">A token to cancel the receive.</param>
    /// <returns>The number of bytes written into <paramref name="buffer"/>.</returns>
    ValueTask<int> ReceiveAsync(
        Memory<byte> buffer,
        CancellationToken cancellationToken = default);
}
