# Dtls usage

This page shows the intended public API shape for Dtls; the examples are planned and illustrative until the corresponding API surface is finalized.

## Datagram-oriented model

Dtls is message-oriented rather than stream-oriented, so applications send and receive datagrams through a `DtlsConnection`.

The planned API separates the transport-agnostic DTLS core from a built-in UDP socket adapter, with planned types such as `IDatagramTransport`, `DtlsClient`, `DtlsServer`, and `DtlsConnection`.

The examples omit `ConfigureAwait` for readability and keep cancellation explicit through `CancellationToken` parameters.

## UDP client with certificate validation

```csharp
using System.Net;
using System.Security.Cryptography.X509Certificates;
using Dtls;

CancellationToken ct = cancellationToken;

await using IDatagramTransport transport =
    await UdpDatagramTransport.ConnectAsync("example.com", 4433, ct);

var client = new DtlsClient(new DtlsClientOptions
{
    TargetHost = "example.com",
    VersionPolicy = DtlsVersionPolicy.Prefer13Allow12Fallback,
    CertificateValidationCallback = static context =>
    {
        X509Chain chain = context.Chain;
        X509Certificate2 certificate = context.Certificate;

        return context.PolicyErrors == DtlsPolicyErrors.None;
    }
});

await using DtlsConnection connection = await client.ConnectAsync(transport, ct);

ReadOnlyMemory<byte> request = "ping"u8.ToArray();
await connection.SendAsync(request, ct);

byte[] buffer = new byte[2048];
DtlsReceiveResult received = await connection.ReceiveAsync(buffer, ct);

ReadOnlyMemory<byte> response = buffer.AsMemory(0, received.Count);
```

## UDP server with a server certificate

```csharp
using System.Net;
using System.Security.Cryptography.X509Certificates;
using Dtls;

CancellationToken ct = cancellationToken;

X509Certificate2 serverCertificate =
    X509CertificateLoader.LoadPkcs12FromFile("server.pfx", password: null);

await using IDatagramTransport listener =
    UdpDatagramTransport.Listen(new IPEndPoint(IPAddress.Any, 4433));

var server = new DtlsServer(new DtlsServerOptions
{
    ServerCertificate = serverCertificate,
    VersionPolicy = DtlsVersionPolicy.Dtls12And13
});

await foreach (DtlsConnection connection in server.AcceptConnectionsAsync(listener, ct))
{
    _ = HandleConnectionAsync(connection, ct);
}

static async Task HandleConnectionAsync(DtlsConnection connection, CancellationToken ct)
{
    await using (connection)
    {
        byte[] buffer = new byte[2048];

        while (!ct.IsCancellationRequested)
        {
            DtlsReceiveResult received = await connection.ReceiveAsync(buffer, ct);
            ReadOnlyMemory<byte> message = buffer.AsMemory(0, received.Count);

            await connection.SendAsync(message, ct);
        }
    }
}
```

## PSK client and server

```csharp
using System.Net;
using Dtls;

CancellationToken ct = cancellationToken;

byte[] sharedKey = Convert.FromHexString(
    "00112233445566778899AABBCCDDEEFF00112233445566778899AABBCCDDEEFF");

var client = new DtlsClient(new DtlsClientOptions
{
    VersionPolicy = DtlsVersionPolicy.Dtls13Only,
    PskIdentity = "device-42",
    PskKeyProvider = static (identity, state) =>
    {
        byte[] key = (byte[])state;
        return identity == "device-42" ? key : null;
    },
    PskKeyProviderState = sharedKey
});

var server = new DtlsServer(new DtlsServerOptions
{
    VersionPolicy = DtlsVersionPolicy.Dtls13Only,
    PskKeyProvider = static (identity, state) =>
    {
        byte[] key = (byte[])state;
        return identity == "device-42" ? key : null;
    },
    PskKeyProviderState = sharedKey
});

await using IDatagramTransport clientTransport =
    await UdpDatagramTransport.ConnectAsync("127.0.0.1", 4433, ct);

await using IDatagramTransport serverTransport =
    UdpDatagramTransport.Listen(new IPEndPoint(IPAddress.Loopback, 4433));

await using DtlsConnection clientConnection =
    await client.ConnectAsync(clientTransport, ct);

await using DtlsConnection serverConnection =
    await server.AcceptConnectionAsync(serverTransport, ct);

await clientConnection.SendAsync("hello"u8.ToArray(), ct);

byte[] buffer = new byte[1024];
DtlsReceiveResult received = await serverConnection.ReceiveAsync(buffer, ct);
```

## Notes on planned APIs

The names and option shapes shown here are illustrative and may change before the public API is finalized.

The intended stable behavior is the datagram-oriented model, explicit version policy, transport abstraction, strict default certificate validation, callback-based PSK and Raw Public Key trust decisions, and built-in UDP socket support.
