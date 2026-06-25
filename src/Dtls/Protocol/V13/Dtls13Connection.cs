// Copyright (c) marcschier. All rights reserved.
// Licensed under the MIT License. See LICENSE in the project root for license information.

using System;
using System.Buffers;
using System.Security.Cryptography;
using System.Threading;
using System.Threading.Tasks;
using Dtls.Crypto;
using Dtls.Protocol.V13.Handshake;
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
    private const ushort InitialApplicationEpoch = 3;

    private readonly IDatagramTransport _transport;
    private readonly Dtls13CipherSuite _suite;
    private readonly HashAlgorithmName _hash;
    private readonly int _maxDatagramSize;
    private readonly SemaphoreSlim _sendLock = new(1, 1);

    private Dtls13RecordProtector _sendProtector;
    private Dtls13RecordProtector _receiveProtector;
    private byte[] _sendSecret;
    private byte[] _receiveSecret;
    private readonly byte[] _sendConnectionId;
    private readonly int _receiveConnectionIdLength;
    private ushort _sendEpoch = InitialApplicationEpoch;
    private ushort _receiveEpoch = InitialApplicationEpoch;
    private ulong _sendSequence;
    private ushort _postHandshakeSendSequence;
    private bool _pendingKeyUpdateResponse;
    private bool _peerClosed;
    private bool _disposed;

    private Dtls13Connection(
        IDatagramTransport transport,
        Dtls13CipherSuite suite,
        Dtls13RecordProtector sendProtector,
        Dtls13RecordProtector receiveProtector,
        byte[] sendSecret,
        byte[] receiveSecret,
        byte[] sendConnectionId,
        int receiveConnectionIdLength)
    {
        _transport = transport;
        _suite = suite;
        _hash = suite.HashAlgorithm;
        _sendProtector = sendProtector;
        _receiveProtector = receiveProtector;
        _sendSecret = sendSecret;
        _receiveSecret = receiveSecret;
        _sendConnectionId = sendConnectionId;
        _receiveConnectionIdLength = receiveConnectionIdLength;
        _maxDatagramSize = transport.MaxDatagramSize;
    }

    /// <inheritdoc />
    public override DtlsProtocolVersion NegotiatedVersion => DtlsProtocolVersion.Dtls13;

    /// <summary>
    /// Creates a connection, deriving the epoch-3 send/receive record protectors from the
    /// supplied application traffic secrets. The secrets are copied so the caller may zero its
    /// own copies; the connection retains them to advance keys on KeyUpdate. When a Connection ID
    /// was negotiated (RFC 9146), <paramref name="sendConnectionId"/> is placed on outbound records
    /// and inbound records are parsed expecting <paramref name="receiveConnectionIdLength"/> CID
    /// bytes.
    /// </summary>
    public static Dtls13Connection Create(
        IDatagramTransport transport,
        Dtls13CipherSuite suite,
        ReadOnlySpan<byte> sendSecret,
        ReadOnlySpan<byte> receiveSecret,
        ReadOnlySpan<byte> sendConnectionId = default,
        int receiveConnectionIdLength = 0)
    {
        Dtls13RecordProtector? send = null;
        Dtls13RecordProtector? receive = null;
        try
        {
            send = BuildProtector(suite, sendSecret, 0);
            receive = BuildProtector(suite, receiveSecret, receiveConnectionIdLength);
            Dtls13Connection connection = new(
                transport,
                suite,
                send,
                receive,
                sendSecret.ToArray(),
                receiveSecret.ToArray(),
                sendConnectionId.ToArray(),
                receiveConnectionIdLength);
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
        ReadOnlySpan<byte> trafficSecret,
        int connectionIdLength)
    {
        return new Dtls13RecordProtector(
            Dtls13RecordKeys.Derive(suite, trafficSecret), connectionIdLength);
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

    /// <inheritdoc />
    public override async ValueTask UpdateKeyAsync(
        bool requestPeerUpdate = false,
        CancellationToken cancellationToken = default)
    {
        ThrowIfDisposed();

        await _sendLock.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            await SendKeyUpdateLockedAsync(requestPeerUpdate, cancellationToken)
                .ConfigureAwait(false);
        }
        finally
        {
            _sendLock.Release();
        }
    }

    // Seals one record at the current send epoch and transmits it. The caller holds _sendLock.
    private async ValueTask SendRecordLockedAsync(
        byte contentType,
        ReadOnlyMemory<byte> payload,
        CancellationToken cancellationToken)
    {
        ulong sequenceNumber = _sendSequence;
        _sendSequence++;

        int sealedLength = _sendProtector.GetSealedLength(
            _sendConnectionId.Length, sequenceNumber, payload.Length);
        byte[] buffer = ArrayPool<byte>.Shared.Rent(sealedLength);
        try
        {
            int written = _sendProtector.Seal(
                _sendEpoch,
                sequenceNumber,
                contentType,
                payload.Span,
                _sendConnectionId,
                buffer);

            await _transport.SendAsync(buffer.AsMemory(0, written), cancellationToken)
                .ConfigureAwait(false);
        }
        finally
        {
            ArrayPool<byte>.Shared.Return(buffer);
        }
    }

    // Sends a KeyUpdate handshake message then advances this endpoint's send keys. Holds _sendLock.
    private async ValueTask SendKeyUpdateLockedAsync(
        bool requestPeerUpdate,
        CancellationToken cancellationToken)
    {
        byte[] body = { requestPeerUpdate ? (byte)1 : (byte)0 };
        byte[] message = HandshakeMessage.Serialize(
            HandshakeType.KeyUpdate, _postHandshakeSendSequence, body);
        _postHandshakeSendSequence++;

        await SendRecordLockedAsync(
                Dtls13PlaintextRecord.HandshakeContentType, message, cancellationToken)
            .ConfigureAwait(false);

        AdvanceSendKeys();
    }

    private void AdvanceSendKeys()
    {
        byte[] next = Dtls13KeySchedule.NextApplicationTrafficSecret(_hash, _sendSecret);
        CryptographicOperations.ZeroMemory(_sendSecret);
        _sendSecret = next;

        Dtls13RecordProtector previous = _sendProtector;
        _sendProtector = BuildProtector(_suite, _sendSecret, 0);
        previous.Dispose();

        _sendEpoch++;
        _sendSequence = 0;
    }

    private void AdvanceReceiveKeys()
    {
        byte[] next = Dtls13KeySchedule.NextApplicationTrafficSecret(_hash, _receiveSecret);
        CryptographicOperations.ZeroMemory(_receiveSecret);
        _receiveSecret = next;

        Dtls13RecordProtector previous = _receiveProtector;
        _receiveProtector = BuildProtector(_suite, _receiveSecret, _receiveConnectionIdLength);
        previous.Dispose();

        _receiveEpoch++;
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

                if (_pendingKeyUpdateResponse)
                {
                    _pendingKeyUpdateResponse = false;
                    await _sendLock.WaitAsync(cancellationToken).ConfigureAwait(false);
                    try
                    {
                        await SendKeyUpdateLockedAsync(false, cancellationToken)
                            .ConfigureAwait(false);
                    }
                    finally
                    {
                        _sendLock.Release();
                    }
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
            if (!Dtls13RecordHeader.TryParse(
                    remaining, _receiveConnectionIdLength, out var header))
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

                if (contentType == Dtls13PlaintextRecord.HandshakeContentType)
                {
                    HandleInboundHandshake(plaintext);
                }

                // Other post-handshake records (e.g. ACKs) are ignored here.
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

    private void HandleInboundHandshake(ReadOnlySpan<byte> plaintext)
    {
        if (!HandshakeMessage.TryParse(
                plaintext, out HandshakeMessageHeader header, out ReadOnlySpan<byte> body))
        {
            return;
        }

        if (header.MessageType != HandshakeType.KeyUpdate || body.Length < 1)
        {
            return;
        }

        AdvanceReceiveKeys();

        // update_requested(1): respond with our own KeyUpdate (sent from the receive loop). The
        // response always uses update_not_requested to avoid an update loop (RFC 8446 §4.6.3).
        if (body[0] == 1)
        {
            _pendingKeyUpdateResponse = true;
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
            _sendLock.Dispose();
        }

        CryptographicOperations.ZeroMemory(_sendSecret);
        CryptographicOperations.ZeroMemory(_receiveSecret);
        _disposed = true;
    }
}
