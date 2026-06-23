using System;
using System.Buffers;
using System.Threading;
using System.Threading.Tasks;
using Dtls.Crypto;
using Dtls.Transport;

namespace Dtls.Protocol.V13;

/// <summary>
/// An established DTLS 1.3 connection. It owns the two epoch-3 application-data record
/// protectors (one to send, one to receive) and the underlying transport. Application
/// datagram boundaries are preserved: each <see cref="SendAsync"/> emits exactly one
/// protected record and each <see cref="ReceiveAsync"/> returns one decrypted datagram.
/// </summary>
internal sealed class Dtls13Connection : DtlsConnection
{
    private const ushort ApplicationEpoch = 3;

    private readonly IDatagramTransport _transport;
    private readonly Dtls13RecordProtector _sendProtector;
    private readonly Dtls13RecordProtector _receiveProtector;
    private readonly int _maxDatagramSize;

    private ulong _sendSequence;
    private bool _peerClosed;
    private bool _disposed;

    public Dtls13Connection(
        IDatagramTransport transport,
        Dtls13RecordProtector sendProtector,
        Dtls13RecordProtector receiveProtector)
    {
        _transport = transport ?? throw new ArgumentNullException(nameof(transport));
        _sendProtector = sendProtector ?? throw new ArgumentNullException(nameof(sendProtector));
        _receiveProtector = receiveProtector
            ?? throw new ArgumentNullException(nameof(receiveProtector));
        _maxDatagramSize = transport.MaxDatagramSize;
    }

    /// <inheritdoc />
    public override DtlsProtocolVersion NegotiatedVersion => DtlsProtocolVersion.Dtls13;

    /// <summary>
    /// Creates a connection, deriving the epoch-3 send/receive record protectors from the
    /// supplied application traffic secrets. Ownership of the protectors stays with the
    /// returned connection.
    /// </summary>
    public static Dtls13Connection Create(
        IDatagramTransport transport,
        Dtls13CipherSuite suite,
        ReadOnlySpan<byte> sendSecret,
        ReadOnlySpan<byte> receiveSecret)
    {
        Dtls13RecordProtector? send = null;
        Dtls13RecordProtector? receive = null;
        try
        {
            send = BuildProtector(suite, sendSecret);
            receive = BuildProtector(suite, receiveSecret);
            Dtls13Connection connection = new(transport, send, receive);
            send = null;
            receive = null;
            return connection;
        }
        finally
        {
            send?.Dispose();
            receive?.Dispose();
        }
    }

    private static Dtls13RecordProtector BuildProtector(
        Dtls13CipherSuite suite,
        ReadOnlySpan<byte> trafficSecret)
    {
        return new Dtls13RecordProtector(Dtls13RecordKeys.Derive(suite, trafficSecret));
    }

    /// <inheritdoc />
    public override async ValueTask SendAsync(
        ReadOnlyMemory<byte> data,
        CancellationToken cancellationToken = default)
    {
        ThrowIfDisposed();

        ulong sequenceNumber = _sendSequence;
        _sendSequence++;

        int sealedLength = _sendProtector.GetSealedLength(0, sequenceNumber, data.Length);
        byte[] buffer = ArrayPool<byte>.Shared.Rent(sealedLength);
        try
        {
            int written = _sendProtector.Seal(
                ApplicationEpoch,
                sequenceNumber,
                Dtls13PlaintextRecord.ApplicationDataContentType,
                data.Span,
                ReadOnlySpan<byte>.Empty,
                buffer);

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
        while (!remaining.IsEmpty)
        {
            if (!Dtls13RecordHeader.TryParse(remaining, 0, out var header))
            {
                return false;
            }

            int recordLength = header.HeaderLength + header.EncryptedRecordLength;
            if (recordLength <= 0 || recordLength > remaining.Length)
            {
                return false;
            }

            ReadOnlySpan<byte> record = remaining.Slice(0, recordLength);
            remaining = remaining.Slice(recordLength);

            if (!_receiveProtector.TryOpen(
                    record, out byte contentType, out byte[] plaintext, out _))
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

                // Ignore handshake/ack records during the application-data phase.
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
        ReadOnlySpan<byte> closeNotify = stackalloc byte[] { 1, (byte)DtlsAlert.CloseNotify };
        ulong sequenceNumber = _sendSequence;
        _sendSequence++;

        int sealedLength = _sendProtector.GetSealedLength(0, sequenceNumber, closeNotify.Length);
        byte[] buffer = ArrayPool<byte>.Shared.Rent(sealedLength);
        try
        {
            int written = _sendProtector.Seal(
                ApplicationEpoch,
                sequenceNumber,
                Dtls13PlaintextRecord.AlertContentType,
                closeNotify,
                ReadOnlySpan<byte>.Empty,
                buffer);

            await _transport.SendAsync(buffer.AsMemory(0, written), cancellationToken)
                .ConfigureAwait(false);
        }
        finally
        {
            ArrayPool<byte>.Shared.Return(buffer);
        }
    }

    private void ThrowIfDisposed()
    {
        if (_disposed)
        {
            throw new ObjectDisposedException(nameof(Dtls13Connection));
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
        }

        _disposed = true;
    }
}
