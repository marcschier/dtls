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
/// End-to-end tests for the managed DTLS 1.3 raw-public-key (RFC 7250) server authentication:
/// the server presents a DER SubjectPublicKeyInfo instead of an X.509 certificate, the client
/// pins it through <see cref="DtlsClientOptions.RawPublicKeyValidation"/>, and the two then
/// exchange protected application datagrams.
/// </summary>
public sealed class Dtls13RawPublicKeyHandshakeTests
{
    [Fact]
    public async Task RawPublicKey_FullHandshake_ExchangesProtectedData()
    {
        using X509Certificate2 certificate = CreateEcdsaSelfSigned();
        byte[] expectedSpki = certificate.PublicKey.ExportSubjectPublicKeyInfo();
        byte[]? observedSpki = null;

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
                AllowRawPublicKeys = true,
                RawPublicKeyValidation = spki =>
                {
                    observedSpki = spki.ToArray();
                    return spki.Span.SequenceEqual(expectedSpki);
                },
            };

            Task<DtlsConnection> serverTask = server.AcceptAsync(serverTransport, cts.Token);
            Task<DtlsConnection> clientTask = DtlsClient.ConnectAsync(
                clientTransport, clientOptions, cts.Token);

            DtlsConnection[] connections = await Task.WhenAll(serverTask, clientTask);
            using DtlsConnection serverConnection = connections[0];
            using DtlsConnection clientConnection = connections[1];

            Assert.Equal(DtlsProtocolVersion.Dtls13, serverConnection.NegotiatedVersion);
            Assert.Equal(DtlsProtocolVersion.Dtls13, clientConnection.NegotiatedVersion);

            Assert.NotNull(observedSpki);
            Assert.NotEmpty(observedSpki!);
            Assert.Equal(expectedSpki, observedSpki);

            await AssertEchoAsync(clientConnection, serverConnection, Encoding.ASCII.GetBytes(
                "hello from the rpk client"), cts.Token);
            await AssertEchoAsync(serverConnection, clientConnection, Encoding.ASCII.GetBytes(
                "hello back from the rpk server"), cts.Token);
            await AssertEchoAsync(clientConnection, serverConnection, new byte[] { 4, 3, 2, 1 },
                cts.Token);
        }
    }

    [Fact]
    public async Task RawPublicKey_RejectedByValidation_FailsHandshake()
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
                AllowRawPublicKeys = true,
                RawPublicKeyValidation = _ => false,
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
            AllowRawPublicKeys = true,
        };
    }

    private static X509Certificate2 CreateEcdsaSelfSigned()
    {
        using ECDsa key = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        CertificateRequest request = new(
            "CN=dtls-test-rpk", key, HashAlgorithmName.SHA256);
        DateTimeOffset now = DateTimeOffset.UtcNow;
        return request.CreateSelfSigned(now.AddMinutes(-5), now.AddHours(1));
    }
}

#pragma warning restore CA2025
