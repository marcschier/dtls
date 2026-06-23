using System;
using System.Runtime.InteropServices;
using System.Threading;
using System.Threading.Tasks;
using Dtls.Internal;
using Dtls.Transport;

namespace Dtls.Interop.SecureTransport;

/// <summary>
/// macOS DTLS 1.0/1.2 backend that delegates to Apple's Secure Transport via P/Invoke.
/// Implementation is pending (plan phase 3): it will use
/// <c>SSLCreateContext(kSSLDatagramType)</c> with read/write callbacks. Secure Transport is
/// deprecated by Apple; a Network.framework backend is tracked as future work.
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
        throw NotYetImplemented.Feature("The Secure Transport DTLS 1.0/1.2 client backend");
    }

    public Task<DtlsConnection> AcceptAsync(
        IDatagramTransport transport,
        DtlsServerOptions options,
        ReadOnlyMemory<byte> initialDatagram,
        CancellationToken cancellationToken)
    {
        throw NotYetImplemented.Feature("The Secure Transport DTLS 1.0/1.2 server backend");
    }
}
