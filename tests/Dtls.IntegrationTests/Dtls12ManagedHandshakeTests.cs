using System;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using Dtls.Protocol.V12.Handshake;
using Dtls.Transport;
using Xunit;

// CA2025: the in-memory transports are always awaited (via Task.WhenAll) before the enclosing
// 'using' disposes them, so the handshake tasks never outlive the disposable instances.
#pragma warning disable CA2025

namespace Dtls.IntegrationTests;

/// <summary>
/// End-to-end tests for the managed DTLS 1.2 certificate-authenticated ECDHE handshake: a real
/// client and server complete the handshake (including the HelloVerifyRequest cookie exchange and
/// extended_master_secret) over an in-memory transport with a self-signed server certificate, then
/// exchange protected application datagrams in both directions.
/// </summary>
public sealed class Dtls12ManagedHandshakeTests
{
    [Fact]
    public async Task EcdsaCertificate_FullHandshake_ExchangesProtectedData()
    {
        using X509Certificate2 certificate = CreateEcdsaSelfSigned();
        await RunHandshakeAsync(certificate);
    }

    [Fact]
    public async Task RsaCertificate_FullHandshake_ExchangesProtectedData()
    {
        using X509Certificate2 certificate = CreateRsaSelfSigned();
        await RunHandshakeAsync(certificate);
    }

    [Fact]
    public async Task EcdhePsk_FullHandshake_ExchangesProtectedData()
    {
        byte[] identity = Encoding.ASCII.GetBytes("dtls12-psk-identity");
        byte[] key = RandomNumberGenerator.GetBytes(32);

        (InMemoryDatagramTransport clientTransport, InMemoryDatagramTransport serverTransport) =
            InMemoryDatagramTransport.CreatePair();

        using CancellationTokenSource cts = new(TimeSpan.FromSeconds(15));
        using (clientTransport)
        using (serverTransport)
        {
            DtlsClientOptions clientOptions = new()
            {
                MinimumVersion = DtlsProtocolVersion.Dtls12,
                MaximumVersion = DtlsProtocolVersion.Dtls12,
                PskCallback = _ => new PskCredential(identity, key),
            };

            DtlsServerOptions serverOptions = new()
            {
                MinimumVersion = DtlsProtocolVersion.Dtls12,
                MaximumVersion = DtlsProtocolVersion.Dtls12,
                PskCallback = presented =>
                    presented.Span.SequenceEqual(identity)
                        ? key
                        : ReadOnlyMemory<byte>.Empty,
            };

            Task<DtlsConnection> serverTask = AcceptAsync(
                serverTransport, serverOptions, cts.Token);
            Task<DtlsConnection> clientTask = Dtls12ClientHandshake.RunAsync(
                clientTransport, clientOptions, cts.Token);

            DtlsConnection[] connections = await Task.WhenAll(serverTask, clientTask);
            using DtlsConnection serverConnection = connections[0];
            using DtlsConnection clientConnection = connections[1];

            Assert.Equal(DtlsProtocolVersion.Dtls12, serverConnection.NegotiatedVersion);
            Assert.Equal(DtlsProtocolVersion.Dtls12, clientConnection.NegotiatedVersion);

            await AssertEchoAsync(clientConnection, serverConnection, Encoding.ASCII.GetBytes(
                "hello from the dtls 1.2 ecdhe-psk client"), cts.Token);
            await AssertEchoAsync(serverConnection, clientConnection, Encoding.ASCII.GetBytes(
                "hello back from the dtls 1.2 ecdhe-psk server"), cts.Token);
        }
    }

    [Fact]
    public async Task RawPublicKey_FullHandshake_ExchangesProtectedData()
    {
        using X509Certificate2 certificate = CreateEcdsaSelfSigned();
        byte[] expectedSpki = certificate.PublicKey.ExportSubjectPublicKeyInfo();

        (InMemoryDatagramTransport clientTransport, InMemoryDatagramTransport serverTransport) =
            InMemoryDatagramTransport.CreatePair();

        using CancellationTokenSource cts = new(TimeSpan.FromSeconds(15));
        using (clientTransport)
        using (serverTransport)
        {
            DtlsClientOptions clientOptions = new()
            {
                MinimumVersion = DtlsProtocolVersion.Dtls12,
                MaximumVersion = DtlsProtocolVersion.Dtls12,
                AllowRawPublicKeys = true,
                RawPublicKeyValidation = spki => spki.Span.SequenceEqual(expectedSpki),
            };

            DtlsServerOptions serverOptions = new()
            {
                MinimumVersion = DtlsProtocolVersion.Dtls12,
                MaximumVersion = DtlsProtocolVersion.Dtls12,
                ServerCertificate = certificate,
                AllowRawPublicKeys = true,
            };

            Task<DtlsConnection> serverTask = AcceptAsync(
                serverTransport, serverOptions, cts.Token);
            Task<DtlsConnection> clientTask = Dtls12ClientHandshake.RunAsync(
                clientTransport, clientOptions, cts.Token);

            DtlsConnection[] connections = await Task.WhenAll(serverTask, clientTask);
            using DtlsConnection serverConnection = connections[0];
            using DtlsConnection clientConnection = connections[1];

            Assert.Equal(DtlsProtocolVersion.Dtls12, serverConnection.NegotiatedVersion);
            Assert.Equal(DtlsProtocolVersion.Dtls12, clientConnection.NegotiatedVersion);

            await AssertEchoAsync(clientConnection, serverConnection, Encoding.ASCII.GetBytes(
                "hello from the dtls 1.2 rpk client"), cts.Token);
            await AssertEchoAsync(serverConnection, clientConnection, Encoding.ASCII.GetBytes(
                "hello back from the dtls 1.2 rpk server"), cts.Token);
        }
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
            DtlsClientOptions clientOptions = new()
            {
                MinimumVersion = DtlsProtocolVersion.Dtls12,
                MaximumVersion = DtlsProtocolVersion.Dtls12,
                RemoteCertificateValidation = (_, _, _) => false,
            };

            Task<DtlsConnection> serverTask = AcceptAsync(
                serverTransport, ServerOptions(certificate), cts.Token);
            Task<DtlsConnection> clientTask = Dtls12ClientHandshake.RunAsync(
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

    private static async Task RunHandshakeAsync(X509Certificate2 certificate)
    {
        string thumbprint = certificate.Thumbprint;

        (InMemoryDatagramTransport clientTransport, InMemoryDatagramTransport serverTransport) =
            InMemoryDatagramTransport.CreatePair();

        using CancellationTokenSource cts = new(TimeSpan.FromSeconds(15));
        using (clientTransport)
        using (serverTransport)
        {
            DtlsClientOptions clientOptions = new()
            {
                MinimumVersion = DtlsProtocolVersion.Dtls12,
                MaximumVersion = DtlsProtocolVersion.Dtls12,
                RemoteCertificateValidation = (presented, _, _) =>
                    string.Equals(
                        presented.Thumbprint, thumbprint, StringComparison.OrdinalIgnoreCase),
            };

            Task<DtlsConnection> serverTask = AcceptAsync(
                serverTransport, ServerOptions(certificate), cts.Token);
            Task<DtlsConnection> clientTask = Dtls12ClientHandshake.RunAsync(
                clientTransport, clientOptions, cts.Token);

            DtlsConnection[] connections = await Task.WhenAll(serverTask, clientTask);
            using DtlsConnection serverConnection = connections[0];
            using DtlsConnection clientConnection = connections[1];

            Assert.Equal(DtlsProtocolVersion.Dtls12, serverConnection.NegotiatedVersion);
            Assert.Equal(DtlsProtocolVersion.Dtls12, clientConnection.NegotiatedVersion);

            await AssertEchoAsync(clientConnection, serverConnection, Encoding.ASCII.GetBytes(
                "hello from the dtls 1.2 client"), cts.Token);
            await AssertEchoAsync(serverConnection, clientConnection, Encoding.ASCII.GetBytes(
                "hello back from the dtls 1.2 server"), cts.Token);
            await AssertEchoAsync(clientConnection, serverConnection, new byte[] { 4, 3, 2, 1 },
                cts.Token);
        }
    }

    [Fact]
    public async Task VersionRange_DowngradesToManaged12_WhenServerIsDtls12Only()
    {
        using X509Certificate2 certificate = CreateEcdsaSelfSigned();
        string thumbprint = certificate.Thumbprint;

        (InMemoryDatagramTransport clientTransport, InMemoryDatagramTransport serverTransport) =
            InMemoryDatagramTransport.CreatePair();

        using CancellationTokenSource cts = new(TimeSpan.FromSeconds(15));
        using (clientTransport)
        using (serverTransport)
        {
            // The server speaks only DTLS 1.2; the client offers the default 1.2..1.3 range and
            // must negotiate down to DTLS 1.2 via the managed engine.
            DtlsClientOptions clientOptions = new()
            {
                MinimumVersion = DtlsProtocolVersion.Dtls12,
                MaximumVersion = DtlsProtocolVersion.Dtls13,
                RemoteCertificateValidation = (presented, _, _) =>
                    string.Equals(
                        presented.Thumbprint, thumbprint, StringComparison.OrdinalIgnoreCase),
            };

            Task<DtlsConnection> serverTask = AcceptAsync(
                serverTransport, ServerOptions(certificate), cts.Token);
            Task<DtlsConnection> clientTask = DtlsClient.ConnectAsync(
                clientTransport, clientOptions, cts.Token);

            DtlsConnection[] connections = await Task.WhenAll(serverTask, clientTask);
            using DtlsConnection serverConnection = connections[0];
            using DtlsConnection clientConnection = connections[1];

            Assert.Equal(DtlsProtocolVersion.Dtls12, serverConnection.NegotiatedVersion);
            Assert.Equal(DtlsProtocolVersion.Dtls12, clientConnection.NegotiatedVersion);

            await AssertEchoAsync(clientConnection, serverConnection, Encoding.ASCII.GetBytes(
                "downgraded to dtls 1.2"), cts.Token);
            await AssertEchoAsync(serverConnection, clientConnection, Encoding.ASCII.GetBytes(
                "server reply over dtls 1.2"), cts.Token);
        }
    }

    private static async Task<DtlsConnection> AcceptAsync(
        InMemoryDatagramTransport transport,
        DtlsServerOptions options,
        CancellationToken cancellationToken)
    {
        byte[] buffer = new byte[transport.MaxDatagramSize];
        int received = await transport.ReceiveAsync(buffer, cancellationToken);
        byte[] initialDatagram = buffer.AsSpan(0, received).ToArray();
        return await Dtls12ServerHandshake.RunAsync(
            transport, options, initialDatagram, cancellationToken);
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
            MinimumVersion = DtlsProtocolVersion.Dtls12,
            MaximumVersion = DtlsProtocolVersion.Dtls12,
            ServerCertificate = certificate,
        };
    }

    private static X509Certificate2 CreateEcdsaSelfSigned()
    {
        using ECDsa key = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var request = new CertificateRequest(
            "CN=dtls12-test", key, HashAlgorithmName.SHA256);
        DateTimeOffset now = DateTimeOffset.UtcNow;
        return request.CreateSelfSigned(now.AddMinutes(-5), now.AddHours(1));
    }

    private static X509Certificate2 CreateRsaSelfSigned()
    {
        using RSA key = RSA.Create(2048);
        var request = new CertificateRequest(
            "CN=dtls12-test", key, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        DateTimeOffset now = DateTimeOffset.UtcNow;
        return request.CreateSelfSigned(now.AddMinutes(-5), now.AddHours(1));
    }
}
