using System;
using System.Runtime.InteropServices;
using System.Threading;
using System.Threading.Tasks;
using Dtls.Internal;
using Dtls.Transport;

namespace Dtls.Interop.SecureTransport;

/// <summary>
/// macOS DTLS 1.2 backend that delegates the handshake and record protection to Apple's
/// Secure Transport (<c>Security.framework</c>) via P/Invoke. It drives an
/// <c>SSLCreateContext(kSSLDatagramType)</c> session through read/write I/O callbacks:
/// inbound datagrams are handed to Secure Transport via the read callback and outbound records
/// are queued by the write callback and flushed as datagrams over the transport. Secure
/// Transport is deprecated by Apple; a Network.framework backend is tracked as future work.
/// </summary>
internal sealed class SecureTransportDtlsBackend : INativeDtlsBackend
{
    public bool IsSupported => RuntimeInformation.IsOSPlatform(OSPlatform.OSX);

    public string Name => "Secure Transport";

    public Task<DtlsConnection> ConnectAsync(
        IDatagramTransport transport,
        DtlsClientOptions options,
        CancellationToken cancellationToken)
    {
#if NET8_0_OR_GREATER
        if (!RuntimeInformation.IsOSPlatform(OSPlatform.OSX))
        {
            throw NotYetImplemented.Feature("The Secure Transport DTLS 1.2 client backend");
        }

        return SecureTransportDtlsConnection.ConnectAsync(transport, options, cancellationToken);
#else
        throw NotYetImplemented.Feature("The Secure Transport DTLS 1.2 client backend");
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
            throw NotYetImplemented.Feature("The Secure Transport DTLS 1.2 server backend");
        }

        return SecureTransportDtlsConnection.AcceptAsync(
            transport, options, initialDatagram, cancellationToken);
#else
        throw NotYetImplemented.Feature("The Secure Transport DTLS 1.2 server backend");
#endif
    }
}
