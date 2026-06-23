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
// VSTHRD003: the failure-path tests deliberately await the client/server handshake tasks that
// were started earlier in the same method; there is no foreign synchronization context.
#pragma warning disable CA2025
#pragma warning disable VSTHRD003

namespace Dtls.IntegrationTests;

/// <summary>
/// End-to-end self-interop tests for the Linux OpenSSL DTLS 1.2 backend: our OpenSSL client
/// and our OpenSSL server complete a real <c>libssl</c> handshake over an in-memory transport
/// pair and then exchange protected application datagrams. Both certificate (ECDSA and RSA,
/// with certificate pinning) and PSK authentication are exercised, along with the
/// corresponding rejection paths. The whole test no-ops on non-Linux hosts because the
/// OpenSSL backend is only available there.
/// </summary>
public sealed class OpenSslDtls12Tests
{
    private static readonly byte[] PskIdentity = Encoding.UTF8.GetBytes("dtls-openssl-client");
    private static readonly byte[] PskKey =
    {
        0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
        0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10,
    };

    [Fact]
    public async Task EcdsaCertificate_Dtls12SelfInterop_ExchangesProtectedData()
    {
        if (!RuntimeInformation.IsOSPlatform(OSPlatform.Linux))
        {
            return;
        }

        using X509Certificate2 certificate = CreateEcdsaCertificate();
        await RunCertificateInteropAsync(certificate);
    }

    [Fact]
    public async Task RsaCertificate_Dtls12SelfInterop_ExchangesProtectedData()
    {
        if (!RuntimeInformation.IsOSPlatform(OSPlatform.Linux))
        {
            return;
        }

        using X509Certificate2 certificate = CreateRsaCertificate();
        await RunCertificateInteropAsync(certificate);
    }

    [Fact]
    public async Task Psk_Dtls12SelfInterop_ExchangesProtectedData()
    {
        if (!RuntimeInformation.IsOSPlatform(OSPlatform.Linux))
        {
            return;
        }

        (InMemoryDatagramTransport clientTransport, InMemoryDatagramTransport serverTransport) =
            InMemoryDatagramTransport.CreatePair();

        using CancellationTokenSource cts = new(TimeSpan.FromSeconds(20));
        using (clientTransport)
        using (serverTransport)
        {
            DtlsServer server = new(new DtlsServerOptions
            {
                MinimumVersion = DtlsProtocolVersion.Dtls12,
                MaximumVersion = DtlsProtocolVersion.Dtls12,
                PskCallback = identity =>
                    identity.Span.SequenceEqual(PskIdentity)
                        ? PskKey
                        : ReadOnlyMemory<byte>.Empty,
                HandshakeTimeout = TimeSpan.FromSeconds(20),
            });

            DtlsClientOptions clientOptions = new()
            {
                MinimumVersion = DtlsProtocolVersion.Dtls12,
                MaximumVersion = DtlsProtocolVersion.Dtls12,
                PskCallback = _ => new PskCredential(PskIdentity, PskKey),
                HandshakeTimeout = TimeSpan.FromSeconds(20),
            };

            Task<DtlsConnection> serverTask = server.AcceptAsync(serverTransport, cts.Token);
            Task<DtlsConnection> clientTask = DtlsClient.ConnectAsync(
                clientTransport, clientOptions, cts.Token);

            DtlsConnection[] connections = await Task.WhenAll(serverTask, clientTask);
            using DtlsConnection serverConnection = connections[0];
            using DtlsConnection clientConnection = connections[1];

            Assert.Equal(DtlsProtocolVersion.Dtls12, serverConnection.NegotiatedVersion);
            Assert.Equal(DtlsProtocolVersion.Dtls12, clientConnection.NegotiatedVersion);

            await AssertEchoAsync(clientConnection, serverConnection,
                Encoding.ASCII.GetBytes("hello from the openssl psk client"), cts.Token);
            await AssertEchoAsync(serverConnection, clientConnection,
                Encoding.ASCII.GetBytes("hello back from the openssl psk server"), cts.Token);
        }
    }

    [Fact]
    public async Task Psk_WrongClientKey_Dtls12Handshake_Fails()
    {
        if (!RuntimeInformation.IsOSPlatform(OSPlatform.Linux))
        {
            return;
        }

        (InMemoryDatagramTransport clientTransport, InMemoryDatagramTransport serverTransport) =
            InMemoryDatagramTransport.CreatePair();

        using CancellationTokenSource cts = new(TimeSpan.FromSeconds(30));
        using (clientTransport)
        using (serverTransport)
        {
            DtlsServer server = new(new DtlsServerOptions
            {
                MinimumVersion = DtlsProtocolVersion.Dtls12,
                MaximumVersion = DtlsProtocolVersion.Dtls12,
                PskCallback = identity =>
                    identity.Span.SequenceEqual(PskIdentity)
                        ? PskKey
                        : ReadOnlyMemory<byte>.Empty,
                HandshakeTimeout = TimeSpan.FromSeconds(5),
            });

            byte[] wrongKey = (byte[])PskKey.Clone();
            wrongKey[0] ^= 0xFF;
            DtlsClientOptions clientOptions = new()
            {
                MinimumVersion = DtlsProtocolVersion.Dtls12,
                MaximumVersion = DtlsProtocolVersion.Dtls12,
                PskCallback = _ => new PskCredential(PskIdentity, wrongKey),
                HandshakeTimeout = TimeSpan.FromSeconds(5),
            };

            Task<DtlsConnection> serverTask = server.AcceptAsync(serverTransport, cts.Token);
            Task<DtlsConnection> clientTask = DtlsClient.ConnectAsync(
                clientTransport, clientOptions, cts.Token);

            await Assert.ThrowsAnyAsync<DtlsException>(
                async () => await Task.WhenAll(serverTask, clientTask));
        }
    }

    [Fact]
    public async Task Certificate_RejectedByValidation_Dtls12Handshake_Fails()
    {
        if (!RuntimeInformation.IsOSPlatform(OSPlatform.Linux))
        {
            return;
        }

        using X509Certificate2 certificate = CreateEcdsaCertificate();

        (InMemoryDatagramTransport clientTransport, InMemoryDatagramTransport serverTransport) =
            InMemoryDatagramTransport.CreatePair();

        using CancellationTokenSource cts = new(TimeSpan.FromSeconds(20));
        using (clientTransport)
        using (serverTransport)
        {
            DtlsServer server = new(new DtlsServerOptions
            {
                MinimumVersion = DtlsProtocolVersion.Dtls12,
                MaximumVersion = DtlsProtocolVersion.Dtls12,
                ServerCertificate = certificate,
                HandshakeTimeout = TimeSpan.FromSeconds(20),
            });

            DtlsClientOptions clientOptions = new()
            {
                MinimumVersion = DtlsProtocolVersion.Dtls12,
                MaximumVersion = DtlsProtocolVersion.Dtls12,
                TargetHost = "localhost",
                RemoteCertificateValidation = (_, _, _) => false,
                HandshakeTimeout = TimeSpan.FromSeconds(20),
            };

            Task<DtlsConnection> serverTask = server.AcceptAsync(serverTransport, cts.Token);
            Task<DtlsConnection> clientTask = DtlsClient.ConnectAsync(
                clientTransport, clientOptions, cts.Token);

            await Assert.ThrowsAnyAsync<DtlsException>(() => clientTask);
            await IgnoreAsync(serverTask);
        }
    }

    private static async Task RunCertificateInteropAsync(X509Certificate2 certificate)
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
                MinimumVersion = DtlsProtocolVersion.Dtls12,
                MaximumVersion = DtlsProtocolVersion.Dtls12,
                ServerCertificate = certificate,
                HandshakeTimeout = TimeSpan.FromSeconds(20),
            });

            DtlsClientOptions clientOptions = new()
            {
                MinimumVersion = DtlsProtocolVersion.Dtls12,
                MaximumVersion = DtlsProtocolVersion.Dtls12,
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

            Assert.Equal(DtlsProtocolVersion.Dtls12, serverConnection.NegotiatedVersion);
            Assert.Equal(DtlsProtocolVersion.Dtls12, clientConnection.NegotiatedVersion);

            await AssertEchoAsync(clientConnection, serverConnection, Encoding.ASCII.GetBytes(
                "hello from the openssl client"), cts.Token);
            await AssertEchoAsync(serverConnection, clientConnection, Encoding.ASCII.GetBytes(
                "hello back from the openssl server"), cts.Token);
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

    private static async Task IgnoreAsync(Task<DtlsConnection> task)
    {
        try
        {
            using DtlsConnection connection = await task;
        }
        catch (DtlsException)
        {
        }
        catch (OperationCanceledException)
        {
        }
    }

    private static X509Certificate2 CreateEcdsaCertificate()
    {
        using ECDsa key = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        CertificateRequest request = new(
            "CN=dtls-openssl-ecdsa", key, HashAlgorithmName.SHA256);
        DateTimeOffset now = DateTimeOffset.UtcNow;
        return request.CreateSelfSigned(now.AddMinutes(-5), now.AddHours(1));
    }

    private static X509Certificate2 CreateRsaCertificate()
    {
        using RSA key = RSA.Create(2048);
        CertificateRequest request = new(
            "CN=dtls-openssl-rsa", key, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        DateTimeOffset now = DateTimeOffset.UtcNow;
        return request.CreateSelfSigned(now.AddMinutes(-5), now.AddHours(1));
    }
}

#pragma warning restore CA2025
#pragma warning restore VSTHRD003
