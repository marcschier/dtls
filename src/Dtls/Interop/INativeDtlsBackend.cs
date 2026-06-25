// Copyright (c) marcschier. All rights reserved.
// Licensed under the MIT License. See LICENSE in the project root for license information.

using System;
using System.Threading;
using System.Threading.Tasks;
using Dtls.Transport;

namespace Dtls.Interop;

/// <summary>
/// Abstraction over a host operating system DTLS stack that handles DTLS 1.0 and 1.2.
/// Concrete implementations wrap OpenSSL (Linux), Schannel (Windows), and Secure Transport
/// (macOS). The managed DTLS 1.3 engine sits alongside these in the hybrid design.
/// </summary>
internal interface INativeDtlsBackend
{
    /// <summary>Whether this backend can run on the current operating system.</summary>
    bool IsSupported { get; }

    /// <summary>A short human-readable name for diagnostics (for example, "OpenSSL").</summary>
    string Name { get; }

    /// <summary>Performs a client DTLS 1.0/1.2 handshake over the given transport.</summary>
    Task<DtlsConnection> ConnectAsync(
        IDatagramTransport transport,
        DtlsClientOptions options,
        CancellationToken cancellationToken);

    /// <summary>Performs a server DTLS 1.0/1.2 handshake over the given transport.</summary>
    /// <param name="transport">The per-peer datagram transport.</param>
    /// <param name="options">The server configuration.</param>
    /// <param name="initialDatagram">
    /// The first datagram (the ClientHello) that the routing layer already consumed from the
    /// transport while peeking the offered version. The backend must process it before
    /// reading any further datagrams.
    /// </param>
    /// <param name="cancellationToken">A token to cancel the handshake.</param>
    Task<DtlsConnection> AcceptAsync(
        IDatagramTransport transport,
        DtlsServerOptions options,
        ReadOnlyMemory<byte> initialDatagram,
        CancellationToken cancellationToken);
}
