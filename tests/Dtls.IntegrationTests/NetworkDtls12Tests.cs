using System;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using Dtls;
using Dtls.Transport;
using Xunit;

// CA2025: the in-memory transports are always awaited (via Task.WhenAll) before the enclosing
// 'using' disposes them, so the handshake tasks never outlive the disposable instances.
#pragma warning disable CA2025

namespace Dtls.IntegrationTests;

/// <summary>
/// End-to-end self-interop tests for the macOS Network.framework backend: our Network.framework
/// client and server complete a real DTLS handshake over an in-memory transport pair using a
/// self-signed server certificate, then exchange protected application datagrams. Unlike the
/// deprecated Secure Transport stack (which is limited to DTLS 1.0 on recent macOS),
/// Network.framework negotiates <see cref="DtlsProtocolVersion.Dtls12"/>. The tests no-op on
/// non-macOS hosts because the Network.framework backend is only available there.
/// </summary>
[Collection(AppleKeychainGroup.Name)]
public sealed class NetworkDtls12Tests
{
    [Fact]
    public async Task EcdsaCertificate_Dtls12SelfInterop_ExchangesProtectedData()
    {
        if (!RuntimeInformation.IsOSPlatform(OSPlatform.OSX))
        {
            return;
        }

        using X509Certificate2 certificate = CreateImportableEcdsaCertificate();
        await RunSelfInteropAsync(certificate);
    }

    [Fact]
    public async Task RsaCertificate_Dtls12SelfInterop_ExchangesProtectedData()
    {
        if (!RuntimeInformation.IsOSPlatform(OSPlatform.OSX))
        {
            return;
        }

        using X509Certificate2 certificate = CreateImportableRsaCertificate();
        await RunSelfInteropAsync(certificate);
    }

    private static async Task RunSelfInteropAsync(X509Certificate2 certificate)
    {
        string thumbprint = certificate.Thumbprint;

        (InMemoryDatagramTransport clientTransport, InMemoryDatagramTransport serverTransport) =
            InMemoryDatagramTransport.CreatePair();

        using CancellationTokenSource cts = new(TimeSpan.FromSeconds(25));
        using (clientTransport)
        using (serverTransport)
        {
            DtlsServer server = new(new DtlsServerOptions
            {
                MinimumVersion = DtlsProtocolVersion.Dtls12,
                MaximumVersion = DtlsProtocolVersion.Dtls12,
                ServerCertificate = certificate,
                HandshakeTimeout = TimeSpan.FromSeconds(25),
            });

            DtlsClientOptions clientOptions = new()
            {
                MinimumVersion = DtlsProtocolVersion.Dtls12,
                MaximumVersion = DtlsProtocolVersion.Dtls12,
                TargetHost = "localhost",
                HandshakeTimeout = TimeSpan.FromSeconds(25),
                RemoteCertificateValidation = (presented, _, _) =>
                    string.Equals(
                        presented.Thumbprint,
                        thumbprint,
                        StringComparison.OrdinalIgnoreCase),
            };

            Task<DtlsConnection> serverTask = server.AcceptAsync(serverTransport, cts.Token);
            Task<DtlsConnection> clientTask = DtlsClient.ConnectAsync(
                clientTransport, clientOptions, cts.Token);

            DtlsConnection[] connections = await Task.WhenAll(serverTask, clientTask);
            using DtlsConnection serverConnection = connections[0];
            using DtlsConnection clientConnection = connections[1];

            Assert.Equal(DtlsProtocolVersion.Dtls12, serverConnection.NegotiatedVersion);
            Assert.Equal(DtlsProtocolVersion.Dtls12, clientConnection.NegotiatedVersion);

            await AssertEchoAsync(clientConnection, serverConnection, Encoding.ASCII.GetBytes(
                "hello from the network.framework client"), cts.Token);
            await AssertEchoAsync(serverConnection, clientConnection, Encoding.ASCII.GetBytes(
                "hello back from the network.framework server"), cts.Token);
            await AssertEchoAsync(clientConnection, serverConnection,
                new byte[] { 9, 8, 7, 6, 5, 4, 3, 2, 1, 0 }, cts.Token);
        }
    }

    private static async Task AssertEchoAsync(
        DtlsConnection sender,
        DtlsConnection receiver,
        byte[] payload,
        CancellationToken cancellationToken)
    {
        await sender.SendAsync(payload, cancellationToken);

        byte[] buffer = new byte[payload.Length + 64];
        int read = await receiver.ReceiveAsync(buffer, cancellationToken);

        Assert.Equal(payload.Length, read);
        Assert.Equal(payload, buffer.AsSpan(0, read).ToArray());
    }

    private static X509Certificate2 CreateImportableEcdsaCertificate()
    {
        using ECDsa key = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        CertificateRequest request = new(
            "CN=dtls-network-ecdsa", key, HashAlgorithmName.SHA256);
        DateTimeOffset now = DateTimeOffset.UtcNow;
        using X509Certificate2 ephemeral =
            request.CreateSelfSigned(now.AddMinutes(-5), now.AddHours(1));
        return MakeImportable(ephemeral);
    }

    private static X509Certificate2 CreateImportableRsaCertificate()
    {
        using RSA key = RSA.Create(2048);
        CertificateRequest request = new(
            "CN=dtls-network-rsa", key, HashAlgorithmName.SHA256,
            RSASignaturePadding.Pkcs1);
        DateTimeOffset now = DateTimeOffset.UtcNow;
        using X509Certificate2 ephemeral =
            request.CreateSelfSigned(now.AddMinutes(-5), now.AddHours(1));
        return MakeImportable(ephemeral);
    }

    private static X509Certificate2 MakeImportable(X509Certificate2 ephemeral)
    {
        // The ephemeral, in-memory private key produced by CreateSelfSigned is round-tripped
        // through a PFX with an exportable, persisted key set so Network.framework can import the
        // identity (certificate plus private key) during the handshake.
        string password = Convert.ToBase64String(RandomNumberGenerator.GetBytes(24));
        byte[] pfx = ephemeral.Export(X509ContentType.Pfx, password);
        return AppleTestCertificates.LoadImportable(pfx, password);
    }
}

#pragma warning restore CA2025
