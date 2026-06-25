// Copyright (c) marcschier. All rights reserved.
// Licensed under the MIT License. See LICENSE in the project root for license information.

using System;
using System.Buffers;
using System.Threading;
using System.Threading.Tasks;
using Dtls.Interop;
using Dtls.Protocol.V12;
using Dtls.Protocol.V13;
using Dtls.Protocol.V13.Handshake;
using Dtls.Routing;
using Dtls.Transport;

namespace Dtls;

/// <summary>
/// Accepts inbound (server) DTLS connections. The first datagram of each connection is
/// inspected and routed to the managed DTLS 1.3 engine or the native DTLS 1.0/1.2 backend
/// based on the offered version (the hybrid server design).
/// </summary>
public sealed class DtlsServer
{
    private readonly DtlsServerOptions _options;

    /// <summary>Initializes a new server with the given configuration.</summary>
    /// <param name="options">The server configuration.</param>
    public DtlsServer(DtlsServerOptions options)
    {
        if (options is null)
        {
            throw new ArgumentNullException(nameof(options));
        }

        options.Validate();
        _options = options;
    }

    /// <summary>
    /// Performs a server DTLS handshake over <paramref name="transport"/>, which carries a
    /// single client's datagrams.
    /// </summary>
    /// <param name="transport">The per-peer datagram transport.</param>
    /// <param name="cancellationToken">A token to cancel the handshake.</param>
    /// <returns>An established <see cref="DtlsConnection"/>.</returns>
    public async Task<DtlsConnection> AcceptAsync(
        IDatagramTransport transport,
        CancellationToken cancellationToken = default)
    {
        if (transport is null)
        {
            throw new ArgumentNullException(nameof(transport));
        }

        byte[] buffer = ArrayPool<byte>.Shared.Rent(transport.MaxDatagramSize);
        try
        {
            int received = await transport.ReceiveAsync(buffer, cancellationToken)
                .ConfigureAwait(false);
            byte[] initialDatagram = buffer.AsSpan(0, received).ToArray();
            DtlsRoute route = ClientHelloVersionPeek.Inspect(initialDatagram);

            if (route == DtlsRoute.Unknown)
            {
                // The ClientHello may be fragmented across datagrams (RFC 9147 section 5.5);
                // reassemble it before routing so the offered version becomes observable.
                byte[]? reassembled = await TryReassembleClientHelloAsync(
                        transport, initialDatagram, cancellationToken)
                    .ConfigureAwait(false);
                if (reassembled is not null)
                {
                    initialDatagram = reassembled;
                    route = ClientHelloVersionPeek.Inspect(initialDatagram);
                }
            }

            if (route == DtlsRoute.Managed13)
            {
                return await ManagedDtls13Engine
                    .AcceptAsync(transport, _options, initialDatagram, cancellationToken)
                    .ConfigureAwait(false);
            }

            if (route == DtlsRoute.NativeLegacy)
            {
                return await AcceptNativeAsync(transport, initialDatagram, cancellationToken)
                    .ConfigureAwait(false);
            }

            throw new DtlsException(
                "Unable to determine the DTLS version from the initial ClientHello.");
        }
        finally
        {
            ArrayPool<byte>.Shared.Return(buffer);
        }
    }

    // Reassembles a ClientHello that was fragmented across datagrams (RFC 9147 section 5.5). The
    // first datagram (already received) is offered, then further datagrams are read until the
    // ClientHello is complete; the result is returned as a single-record plaintext datagram so the
    // version peek and the handshake engines can consume it unchanged. Returns null when the first
    // datagram is not a plaintext ClientHello fragment or the peer closes the transport.
    private async Task<byte[]?> TryReassembleClientHelloAsync(
        IDatagramTransport transport,
        byte[] firstDatagram,
        CancellationToken cancellationToken)
    {
        HandshakeReassembler reassembler = new(_options.MaxHandshakeMessageSize, firstSequence: 0);
        if (!Dtls13HandshakeFlight.OfferPlaintext(firstDatagram, reassembler))
        {
            return null;
        }

        byte[] buffer = ArrayPool<byte>.Shared.Rent(transport.MaxDatagramSize);
        try
        {
            while (true)
            {
                if (reassembler.TryReadNext(
                    out HandshakeType type, out byte[] body, out ushort sequence))
                {
                    if (type != HandshakeType.ClientHello)
                    {
                        return null;
                    }

                    byte[] message = HandshakeMessage.Serialize(type, sequence, body);
                    return Dtls13PlaintextRecord.Encode(
                        Dtls13PlaintextRecord.HandshakeContentType, 0, 0, message);
                }

                int received = await transport.ReceiveAsync(buffer, cancellationToken)
                    .ConfigureAwait(false);
                if (received == 0)
                {
                    return null;
                }

                Dtls13HandshakeFlight.OfferPlaintext(buffer.AsSpan(0, received), reassembler);
            }
        }
        finally
        {
            ArrayPool<byte>.Shared.Return(buffer);
        }
    }

    private Task<DtlsConnection> AcceptNativeAsync(
        IDatagramTransport transport,
        ReadOnlyMemory<byte> initialDatagram,
        CancellationToken cancellationToken)
    {
        // Prefer the native OS backend; where none exists (for example Android) the managed
        // DTLS 1.2 engine is the universal fallback.
        INativeDtlsBackend? backend = NativeDtlsBackend.ForCurrentPlatform();
        if (backend is not null)
        {
            return backend.AcceptAsync(transport, _options, initialDatagram, cancellationToken);
        }

        return ManagedDtls12Engine.AcceptAsync(
            transport, _options, initialDatagram, cancellationToken);
    }
}
