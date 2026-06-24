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
/// End-to-end self-interop tests for the macOS Secure Transport backend: our Secure Transport
/// client and server complete a real <c>Security.framework</c> handshake over an in-memory
/// transport pair using a self-signed server certificate, then exchange protected application
/// datagrams. The negotiated version is DTLS 1.0: Apple's deprecated Secure Transport rejects
/// every API for selecting DTLS 1.2 on recent macOS (errSSLBadConfiguration / OSStatus -909),
/// so the datagram context falls back to its default of DTLS 1.0. The tests no-op on non-macOS
/// hosts because the Secure Transport backend is only available there.
/// </summary>
public sealed class SecureTransportDtls10Tests
{
    [Fact]
    public async Task EcdsaCertificate_Dtls10SelfInterop_ExchangesProtectedData()
    {
        if (!RuntimeInformation.IsOSPlatform(OSPlatform.OSX))
        {
            return;
        }

        using X509Certificate2 certificate = CreateSecureTransportUsableEcdsaCertificate();
        await RunSelfInteropAsync(certificate);
    }

    [Fact]
    public async Task RsaCertificate_Dtls10SelfInterop_ExchangesProtectedData()
    {
        if (!RuntimeInformation.IsOSPlatform(OSPlatform.OSX))
        {
            return;
        }

        using X509Certificate2 certificate = CreateSecureTransportUsableRsaCertificate();
        await RunSelfInteropAsync(certificate);
    }

    private static async Task RunSelfInteropAsync(X509Certificate2 certificate)
    {
        string thumbprint = certificate.Thumbprint;

        (InMemoryDatagramTransport clientTransport, InMemoryDatagramTransport serverTransport) =
            InMemoryDatagramTransport.CreatePair();

        using CancellationTokenSource cts = new(TimeSpan.FromSeconds(20));
        using (clientTransport)
        using (serverTransport)
        {
            DtlsServer server = new(new DtlsServerOptions
            {
                MinimumVersion = DtlsProtocolVersion.Dtls10,
                MaximumVersion = DtlsProtocolVersion.Dtls10,
                AllowDeprecatedDtls10 = true,
                ServerCertificate = certificate,
                HandshakeTimeout = TimeSpan.FromSeconds(20),
            });

            DtlsClientOptions clientOptions = new()
            {
                MinimumVersion = DtlsProtocolVersion.Dtls10,
                MaximumVersion = DtlsProtocolVersion.Dtls10,
                AllowDeprecatedDtls10 = true,
                TargetHost = "localhost",
                HandshakeTimeout = TimeSpan.FromSeconds(20),
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

            Assert.Equal(DtlsProtocolVersion.Dtls10, serverConnection.NegotiatedVersion);
            Assert.Equal(DtlsProtocolVersion.Dtls10, clientConnection.NegotiatedVersion);

            await AssertEchoAsync(clientConnection, serverConnection, Encoding.ASCII.GetBytes(
                "hello from the secure transport client"), cts.Token);
            await AssertEchoAsync(serverConnection, clientConnection, Encoding.ASCII.GetBytes(
                "hello back from the secure transport server"), cts.Token);
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

    private static X509Certificate2 CreateSecureTransportUsableEcdsaCertificate()
    {
        using ECDsa key = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        CertificateRequest request = new(
            "CN=dtls-securetransport-ecdsa", key, HashAlgorithmName.SHA256);
        DateTimeOffset now = DateTimeOffset.UtcNow;
        using X509Certificate2 ephemeral =
            request.CreateSelfSigned(now.AddMinutes(-5), now.AddHours(1));
        return MakeSecureTransportUsable(ephemeral);
    }

    private static X509Certificate2 CreateSecureTransportUsableRsaCertificate()
    {
        using RSA key = RSA.Create(2048);
        CertificateRequest request = new(
            "CN=dtls-securetransport-rsa", key, HashAlgorithmName.SHA256,
            RSASignaturePadding.Pkcs1);
        DateTimeOffset now = DateTimeOffset.UtcNow;
        using X509Certificate2 ephemeral =
            request.CreateSelfSigned(now.AddMinutes(-5), now.AddHours(1));
        return MakeSecureTransportUsable(ephemeral);
    }

    private static X509Certificate2 MakeSecureTransportUsable(X509Certificate2 ephemeral)
    {
        // The ephemeral, in-memory private key produced by CreateSelfSigned is round-tripped
        // through a PFX with an exportable, persisted key set so Secure Transport can import
        // the identity (certificate plus private key) during the handshake.
        string password = Convert.ToBase64String(RandomNumberGenerator.GetBytes(24));
        byte[] pfx = ephemeral.Export(X509ContentType.Pfx, password);
        const X509KeyStorageFlags flags =
            X509KeyStorageFlags.Exportable | X509KeyStorageFlags.PersistKeySet;
#if NET9_0_OR_GREATER
        return X509CertificateLoader.LoadPkcs12(pfx, password, flags);
#else
        return new X509Certificate2(pfx, password, flags);
#endif
    }
}

#pragma warning restore CA2025
