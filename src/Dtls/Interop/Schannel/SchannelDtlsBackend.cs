// Copyright (c) marcschier. All rights reserved.
// Licensed under the MIT License. See LICENSE in the project root for license information.

using System;
using System.Runtime.InteropServices;
using System.Threading;
using System.Threading.Tasks;
using Dtls.Internal;
using Dtls.Transport;

namespace Dtls.Interop.Schannel;

/// <summary>
/// Windows DTLS 1.0/1.2 backend that delegates the handshake and record protection to the
/// operating system Schannel SSP via SSPI (<c>secur32.dll</c>). It acquires a Schannel
/// credential with <c>SP_PROT_DTLS1_2_*</c> enabled and drives
/// <c>InitializeSecurityContext</c>/<c>AcceptSecurityContext</c> with the
/// <c>ISC_REQ_DATAGRAM</c>/<c>ASC_REQ_DATAGRAM</c> flags over the datagram transport.
/// </summary>
internal sealed class SchannelDtlsBackend : INativeDtlsBackend
{
    public bool IsSupported => RuntimeInformation.IsOSPlatform(OSPlatform.Windows);

    public string Name => "Schannel";

    public Task<DtlsConnection> ConnectAsync(
        IDatagramTransport transport,
        DtlsClientOptions options,
        CancellationToken cancellationToken)
    {
        if (!RuntimeInformation.IsOSPlatform(OSPlatform.Windows))
        {
            throw NotYetImplemented.Feature("The Schannel DTLS 1.0/1.2 client backend");
        }

        return SchannelDtlsConnection.ConnectAsync(transport, options, cancellationToken);
    }

    public Task<DtlsConnection> AcceptAsync(
        IDatagramTransport transport,
        DtlsServerOptions options,
        ReadOnlyMemory<byte> initialDatagram,
        CancellationToken cancellationToken)
    {
        if (!RuntimeInformation.IsOSPlatform(OSPlatform.Windows))
        {
            throw NotYetImplemented.Feature("The Schannel DTLS 1.0/1.2 server backend");
        }

        return SchannelDtlsConnection.AcceptAsync(
            transport, options, initialDatagram, cancellationToken);
    }
}
