// Copyright (c) marcschier. All rights reserved.
// Licensed under the MIT License. See LICENSE in the project root for license information.

using System;
using System.Runtime.InteropServices;
using System.Threading;
using System.Threading.Tasks;
using Dtls.Internal;
using Dtls.Interop.SecureTransport;
using Dtls.Transport;

namespace Dtls.Interop.Network;

/// <summary>
/// macOS native DTLS backend that prefers Apple's modern <c>Network.framework</c> (which
/// negotiates DTLS 1.2 over secure UDP) and falls back to the deprecated Secure Transport stack
/// (DTLS 1.0) when Network.framework is unavailable or when the caller explicitly requests only
/// DTLS 1.0. Network.framework owns its own UDP socket, so the connection layer bridges it to the
/// application's <see cref="IDatagramTransport"/> through a private loopback relay.
/// </summary>
internal sealed class NetworkDtlsBackend : INativeDtlsBackend
{
    public bool IsSupported => RuntimeInformation.IsOSPlatform(OSPlatform.OSX);

    public string Name => "Network.framework";

    public Task<DtlsConnection> ConnectAsync(
        IDatagramTransport transport,
        DtlsClientOptions options,
        CancellationToken cancellationToken)
    {
#if NET8_0_OR_GREATER
        if (!RuntimeInformation.IsOSPlatform(OSPlatform.OSX))
        {
            throw NotYetImplemented.Feature("The macOS DTLS client backend");
        }

        // Network.framework negotiates DTLS 1.2; Secure Transport covers deprecated DTLS 1.0 and
        // serves as the fallback when Network.framework cannot be resolved on this host.
        if (options.MaximumVersion <= DtlsProtocolVersion.Dtls10
            || !NetworkDtlsConnection.IsAvailable)
        {
            return SecureTransportDtlsConnection.ConnectAsync(
                transport, options, cancellationToken);
        }

        return NetworkDtlsConnection.ConnectAsync(transport, options, cancellationToken);
#else
        throw NotYetImplemented.Feature("The macOS DTLS client backend");
#endif
    }

    public Task<DtlsConnection> AcceptAsync(
        IDatagramTransport transport,
        DtlsServerOptions options,
        ReadOnlyMemory<byte> initialDatagram,
        CancellationToken cancellationToken)
    {
#if NET8_0_OR_GREATER
        if (!RuntimeInformation.IsOSPlatform(OSPlatform.OSX))
        {
            throw NotYetImplemented.Feature("The macOS DTLS server backend");
        }

        if (options.MaximumVersion <= DtlsProtocolVersion.Dtls10
            || !NetworkDtlsConnection.IsAvailable)
        {
            return SecureTransportDtlsConnection.AcceptAsync(
                transport, options, initialDatagram, cancellationToken);
        }

        return NetworkDtlsConnection.AcceptAsync(
            transport, options, initialDatagram, cancellationToken);
#else
        throw NotYetImplemented.Feature("The macOS DTLS server backend");
#endif
    }
}
