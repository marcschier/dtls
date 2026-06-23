using System;
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
/// End-to-end tests for the managed DTLS 1.3 certificate-authenticated (EC)DHE handshake:
/// a real client and server complete the handshake over an in-memory transport using a
/// self-signed server certificate and then exchange protected application datagrams.
/// </summary>
public sealed class Dtls13CertificateHandshakeTests
{
    [Fact]
    public async Task EcdsaCertificate_FullHandshake_ExchangesProtectedData()
    {
        using X509Certificate2 certificate = CreateEcdsaSelfSigned();
        await RunAcceptedHandshakeAsync(certificate);
    }

    [Fact]
    public async Task RsaCertificate_FullHandshake_ExchangesProtectedData()
    {
        using X509Certificate2 certificate = CreateRsaSelfSigned();
        await RunAcceptedHandshakeAsync(certificate);
    }

    [Fact]
    public async Task RejectedCertificate_FailsHandshake()
    {
        using X509Certificate2 certificate = CreateEcdsaSelfSigned();

        (InMemoryDatagramTransport clientTransport, InMemoryDatagramTransport serverTransport) =
            InMemoryDatagramTransport.CreatePair();

        using CancellationTokenSource cts = new(TimeSpan.FromSeconds(10));
        using (clientTransport)
        using (serverTransport)
        {
            DtlsServer server = new(ServerOptions(certificate));

            DtlsClientOptions clientOptions = new()
            {
                MinimumVersion = DtlsProtocolVersion.Dtls13,
                MaximumVersion = DtlsProtocolVersion.Dtls13,
                HandshakeTimeout = TimeSpan.FromSeconds(2),
                RemoteCertificateValidation = (_, _, _) => false,
            };

            Task<DtlsConnection> serverTask = server.AcceptAsync(serverTransport, cts.Token);
            Task<DtlsConnection> clientTask = DtlsClient.ConnectAsync(
                clientTransport, clientOptions, cts.Token);

            bool faulted = false;
            try
            {
                await Task.WhenAll(serverTask, clientTask);
            }
            catch (DtlsException)
            {
                faulted = true;
            }

            Assert.True(faulted);
            Assert.True(clientTask.IsFaulted);
        }
    }

    private static async Task RunAcceptedHandshakeAsync(X509Certificate2 certificate)
    {
        string thumbprint = certificate.Thumbprint;

        (InMemoryDatagramTransport clientTransport, InMemoryDatagramTransport serverTransport) =
            InMemoryDatagramTransport.CreatePair();

        using CancellationTokenSource cts = new(TimeSpan.FromSeconds(10));
        using (clientTransport)
        using (serverTransport)
        {
            DtlsServer server = new(ServerOptions(certificate));

            DtlsClientOptions clientOptions = new()
            {
                MinimumVersion = DtlsProtocolVersion.Dtls13,
                MaximumVersion = DtlsProtocolVersion.Dtls13,
                HandshakeTimeout = TimeSpan.FromSeconds(10),
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

            Assert.Equal(DtlsProtocolVersion.Dtls13, serverConnection.NegotiatedVersion);
            Assert.Equal(DtlsProtocolVersion.Dtls13, clientConnection.NegotiatedVersion);

            await AssertEchoAsync(clientConnection, serverConnection, Encoding.ASCII.GetBytes(
                "hello from the cert client"), cts.Token);
            await AssertEchoAsync(serverConnection, clientConnection, Encoding.ASCII.GetBytes(
                "hello back from the cert server"), cts.Token);
            await AssertEchoAsync(clientConnection, serverConnection, new byte[] { 9, 8, 7, 6 },
                cts.Token);
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

    private static DtlsServerOptions ServerOptions(X509Certificate2 certificate)
    {
        return new DtlsServerOptions
        {
            MinimumVersion = DtlsProtocolVersion.Dtls13,
            MaximumVersion = DtlsProtocolVersion.Dtls13,
            ServerCertificate = certificate,
        };
    }

    private static X509Certificate2 CreateEcdsaSelfSigned()
    {
        using ECDsa key = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        CertificateRequest request = new(
            "CN=dtls-test-ecdsa", key, HashAlgorithmName.SHA256);
        DateTimeOffset now = DateTimeOffset.UtcNow;
        return request.CreateSelfSigned(now.AddMinutes(-5), now.AddHours(1));
    }

    private static X509Certificate2 CreateRsaSelfSigned()
    {
        using RSA key = RSA.Create(2048);
        CertificateRequest request = new(
            "CN=dtls-test-rsa",
            key,
            HashAlgorithmName.SHA256,
            RSASignaturePadding.Pss);
        DateTimeOffset now = DateTimeOffset.UtcNow;
        return request.CreateSelfSigned(now.AddMinutes(-5), now.AddHours(1));
    }
}

#pragma warning restore CA2025
