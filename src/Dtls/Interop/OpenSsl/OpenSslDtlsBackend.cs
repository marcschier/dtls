using System;
using System.Runtime.InteropServices;
using System.Threading;
using System.Threading.Tasks;
using Dtls.Internal;
using Dtls.Transport;

namespace Dtls.Interop.OpenSsl;

/// <summary>
/// Linux DTLS 1.0/1.2 backend that delegates to OpenSSL (libssl/libcrypto) via P/Invoke.
/// Implementation is pending (plan phase 3): it will use <c>DTLS_method</c>, a memory BIO
/// pair to feed datagrams, and <c>DTLSv1_listen</c> for stateless server cookies.
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
        throw NotYetImplemented.Feature("The OpenSSL DTLS 1.0/1.2 client backend");
    }

    public Task<DtlsConnection> AcceptAsync(
        IDatagramTransport transport,
        DtlsServerOptions options,
        ReadOnlyMemory<byte> initialDatagram,
        CancellationToken cancellationToken)
    {
        throw NotYetImplemented.Feature("The OpenSSL DTLS 1.0/1.2 server backend");
    }
}
