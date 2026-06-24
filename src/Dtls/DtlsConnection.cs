using System;
using System.Threading;
using System.Threading.Tasks;

namespace Dtls;

/// <summary>
/// An established DTLS connection over which application datagrams can be exchanged.
/// Datagram boundaries are preserved: each <see cref="SendAsync"/> produces one protected
/// record and each <see cref="ReceiveAsync"/> returns one decrypted application datagram.
/// </summary>
public abstract class DtlsConnection : IDisposable
{
    /// <summary>The DTLS version negotiated for this connection.</summary>
    public abstract DtlsProtocolVersion NegotiatedVersion { get; }

    /// <summary>
    /// Encrypts and sends a single application datagram to the peer.
    /// </summary>
    /// <param name="data">The application data to send.</param>
    /// <param name="cancellationToken">A token to cancel the operation.</param>
    public abstract ValueTask SendAsync(
        ReadOnlyMemory<byte> data,
        CancellationToken cancellationToken = default);

    /// <summary>
    /// Receives and decrypts the next application datagram into <paramref name="buffer"/>.
    /// </summary>
    /// <param name="buffer">The destination buffer.</param>
    /// <param name="cancellationToken">A token to cancel the operation.</param>
    /// <returns>The number of plaintext bytes written, or 0 on orderly closure.</returns>
    public abstract ValueTask<int> ReceiveAsync(
        Memory<byte> buffer,
        CancellationToken cancellationToken = default);

    /// <summary>
    /// Sends a close_notify alert and gracefully closes the connection.
    /// </summary>
    /// <param name="cancellationToken">A token to cancel the operation.</param>
    public abstract ValueTask CloseAsync(CancellationToken cancellationToken = default);

    /// <summary>
    /// Initiates a post-handshake key update (RFC 8446 section 4.6.3 / RFC 9147), rotating this
    /// endpoint's send keys to the next generation and incrementing its epoch. When
    /// <paramref name="requestPeerUpdate"/> is <see langword="true"/>, the peer is asked to update
    /// and send its own KeyUpdate in return. Only DTLS 1.3 connections support this; other
    /// versions throw <see cref="NotSupportedException"/>.
    /// </summary>
    /// <param name="requestPeerUpdate">Whether to ask the peer to update its keys too.</param>
    /// <param name="cancellationToken">A token to cancel the operation.</param>
    public virtual ValueTask UpdateKeyAsync(
        bool requestPeerUpdate = false,
        CancellationToken cancellationToken = default) =>
        throw new NotSupportedException(
            "KeyUpdate is only supported for DTLS 1.3 connections.");

    /// <inheritdoc />
    public void Dispose()
    {
        Dispose(true);
        GC.SuppressFinalize(this);
    }

    /// <summary>Releases resources held by the connection.</summary>
    /// <param name="disposing">Whether the call originates from <see cref="Dispose()"/>.</param>
    protected abstract void Dispose(bool disposing);
}
