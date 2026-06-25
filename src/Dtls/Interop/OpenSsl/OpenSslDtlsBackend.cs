// Copyright (c) marcschier. All rights reserved.
// Licensed under the MIT License. See LICENSE in the project root for license information.

using System;
using System.Runtime.InteropServices;
using System.Threading;
using System.Threading.Tasks;
using Dtls.Internal;
using Dtls.Transport;

namespace Dtls.Interop.OpenSsl;

/// <summary>
/// Linux DTLS 1.2 backend that delegates the handshake and record protection to OpenSSL
/// (<c>libssl</c>/<c>libcrypto</c>) via P/Invoke. It drives <c>DTLS_method</c> over a pair of
/// memory BIOs: inbound datagrams are written to the read BIO and OpenSSL's outbound records
/// are drained from the write BIO and flushed as datagrams over the transport.
/// </summary>
internal sealed class OpenSslDtlsBackend : INativeDtlsBackend
{
    public bool IsSupported => RuntimeInformation.IsOSPlatform(OSPlatform.Linux);

    public string Name => "OpenSSL";

    public Task<DtlsConnection> ConnectAsync(
        IDatagramTransport transport,
        DtlsClientOptions options,
        CancellationToken cancellationToken)
    {
#if NET8_0_OR_GREATER
        if (!RuntimeInformation.IsOSPlatform(OSPlatform.Linux))
        {
            throw NotYetImplemented.Feature("The OpenSSL DTLS 1.2 client backend");
        }

        return OpenSslDtlsConnection.ConnectAsync(transport, options, cancellationToken);
#else
        throw NotYetImplemented.Feature("The OpenSSL DTLS 1.2 client backend");
#endif
    }

    public Task<DtlsConnection> AcceptAsync(
        IDatagramTransport transport,
        DtlsServerOptions options,
        ReadOnlyMemory<byte> initialDatagram,
        CancellationToken cancellationToken)
    {
#if NET8_0_OR_GREATER
        if (!RuntimeInformation.IsOSPlatform(OSPlatform.Linux))
        {
            throw NotYetImplemented.Feature("The OpenSSL DTLS 1.2 server backend");
        }

        return OpenSslDtlsConnection.AcceptAsync(
            transport, options, initialDatagram, cancellationToken);
#else
        throw NotYetImplemented.Feature("The OpenSSL DTLS 1.2 server backend");
#endif
    }
}
