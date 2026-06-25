// Copyright (c) marcschier. All rights reserved.
// Licensed under the MIT License. See LICENSE in the project root for license information.

using System;
using System.Buffers;
using System.Threading;
using System.Threading.Tasks;
using Dtls.Protocol.V12.Handshake;
using Dtls.Protocol.V13;
using Dtls.Transport;

namespace Dtls.Protocol.V12;

/// <summary>
/// An established DTLS 1.2 connection. It owns the epoch-1 AEAD record protectors (one to send,
/// one to receive) and the underlying transport. Application datagram boundaries are preserved:
/// each <see cref="SendAsync"/> emits exactly one protected record and each
/// <see cref="ReceiveAsync"/> returns one decrypted datagram. The send sequence starts at 1 because
/// the handshake Finished consumed epoch-1 sequence number 0.
/// </summary>
internal sealed class Dtls12Connection : DtlsConnection
{
    private const ushort ApplicationEpoch = 1;

    private readonly IDatagramTransport _transport;
    private readonly Dtls12RecordProtector _sendProtector;
    private readonly Dtls12RecordProtector _receiveProtector;
    private readonly int _maxDatagramSize;
    private readonly SemaphoreSlim _sendLock = new(1, 1);
    private ulong _sendSequence;
    private bool _peerClosed;
    private bool _disposed;

    private Dtls12Connection(
        IDatagramTransport transport,
        Dtls12RecordProtector sendProtector,
        Dtls12RecordProtector receiveProtector,
        ulong sendSequenceStart)
    {
        _transport = transport;
        _sendProtector = sendProtector;
        _receiveProtector = receiveProtector;
        _sendSequence = sendSequenceStart;
        _maxDatagramSize = transport.MaxDatagramSize;
    }

    /// <inheritdoc />
    public override DtlsProtocolVersion NegotiatedVersion => DtlsProtocolVersion.Dtls12;

    /// <summary>
    /// Creates a connection from the supplied epoch-1 send/receive record protectors. The
    /// protectors are owned by the connection. <paramref name="sendSequenceStart"/> is the next
    /// epoch-1 send
    /// sequence number (1 after the handshake Finished).
    /// </summary>
    public static Dtls12Connection Create(
        IDatagramTransport transport,
        Dtls12RecordProtector sendProtector,
        Dtls12RecordProtector receiveProtector,
        ulong sendSequenceStart)
    {
        return new Dtls12Connection(
            transport, sendProtector, receiveProtector, sendSequenceStart);
    }

    /// <inheritdoc />
    public override async ValueTask SendAsync(
        ReadOnlyMemory<byte> data,
        CancellationToken cancellationToken = default)
    {
        ThrowIfDisposed();

        await _sendLock.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            await SendRecordLockedAsync(
                    Dtls13PlaintextRecord.ApplicationDataContentType, data, cancellationToken)
                .ConfigureAwait(false);
        }
        finally
        {
            _sendLock.Release();
        }
    }

    private async ValueTask SendRecordLockedAsync(
        byte contentType,
        ReadOnlyMemory<byte> payload,
        CancellationToken cancellationToken)
    {
        ulong sequenceNumber = _sendSequence;
        _sendSequence++;

        int sealedLength = _sendProtector.GetSealedLength(payload.Length);
        byte[] buffer = ArrayPool<byte>.Shared.Rent(sealedLength);
        try
        {
            int written = _sendProtector.Seal(
                ApplicationEpoch, sequenceNumber, contentType, payload.Span, buffer);
            await _transport.SendAsync(buffer.AsMemory(0, written), cancellationToken)
                .ConfigureAwait(false);
        }
        finally
        {
            ArrayPool<byte>.Shared.Return(buffer);
        }
    }

    /// <inheritdoc />
    public override async ValueTask<int> ReceiveAsync(
        Memory<byte> buffer,
        CancellationToken cancellationToken = default)
    {
        ThrowIfDisposed();

        if (_peerClosed)
        {
            return 0;
        }

        byte[] datagram = ArrayPool<byte>.Shared.Rent(_maxDatagramSize);
        try
        {
            while (true)
            {
                int received = await _transport
                    .ReceiveAsync(datagram, cancellationToken)
                    .ConfigureAwait(false);
                if (received == 0)
                {
                    _peerClosed = true;
                    return 0;
                }

                if (TryHandleDatagram(
                        datagram.AsSpan(0, received),
                        buffer.Span,
                        out int plaintextLength,
                        out bool closed))
                {
                    if (closed)
                    {
                        _peerClosed = true;
                        return 0;
                    }

                    return plaintextLength;
                }
            }
        }
        finally
        {
            ArrayPool<byte>.Shared.Return(datagram);
        }
    }

    private bool TryHandleDatagram(
        ReadOnlySpan<byte> datagram,
        Span<byte> destination,
        out int plaintextLength,
        out bool closed)
    {
        plaintextLength = 0;
        closed = false;

        ReadOnlySpan<byte> remaining = datagram;
        while (Dtls13PlaintextRecord.TryParse(
            remaining, out _, out _, out _, out _, out int consumed))
        {
            ReadOnlySpan<byte> record = remaining.Slice(0, consumed);
            remaining = remaining.Slice(consumed);

            if (!_receiveProtector.TryOpen(
                    record, out byte contentType, out byte[] plaintext, out _, out _, out _))
            {
                continue;
            }

            try
            {
                if (contentType == Dtls13PlaintextRecord.ApplicationDataContentType)
                {
                    if (plaintext.Length > destination.Length)
                    {
                        throw new DtlsException(
                            "The receive buffer is smaller than the decrypted datagram.");
                    }

                    plaintext.CopyTo(destination);
                    plaintextLength = plaintext.Length;
                    return true;
                }

                if (contentType == Dtls13PlaintextRecord.AlertContentType
                    && plaintext.Length >= 2
                    && plaintext[1] == (byte)DtlsAlert.CloseNotify)
                {
                    closed = true;
                    return true;
                }
            }
            finally
            {
                Array.Clear(plaintext, 0, plaintext.Length);
            }
        }

        return false;
    }

    /// <inheritdoc />
    public override async ValueTask CloseAsync(CancellationToken cancellationToken = default)
    {
        if (_disposed)
        {
            return;
        }

        // alert: level=warning(1), description=close_notify(0).
        byte[] closeNotify = { 1, (byte)DtlsAlert.CloseNotify };
        await _sendLock.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            await SendRecordLockedAsync(
                    Dtls13PlaintextRecord.AlertContentType, closeNotify, cancellationToken)
                .ConfigureAwait(false);
        }
        finally
        {
            _sendLock.Release();
        }
    }

    private void ThrowIfDisposed()
    {
        if (_disposed)
        {
            throw new ObjectDisposedException(nameof(Dtls12Connection));
        }
    }

    /// <inheritdoc />
    protected override void Dispose(bool disposing)
    {
        if (_disposed)
        {
            return;
        }

        if (disposing)
        {
            _sendProtector.Dispose();
            _receiveProtector.Dispose();
            _sendLock.Dispose();
        }

        _disposed = true;
    }
}
