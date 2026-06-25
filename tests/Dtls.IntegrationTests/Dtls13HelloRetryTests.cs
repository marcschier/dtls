// Copyright (c) marcschier. All rights reserved.
// Licensed under the MIT License. See LICENSE in the project root for license information.

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
/// End-to-end tests for the DTLS 1.3 stateless HelloRetryRequest cookie exchange
/// (RFC 9147 section 5.1 / RFC 8446 section 4.1.4): when the server enables a stateless retry
/// it answers the first ClientHello with a HelloRetryRequest carrying a cookie (and a
/// corrected key_share group); the client resends a second ClientHello and the handshake
/// completes with the synthetic <c>message_hash</c> transcript on both sides.
/// </summary>
public sealed class Dtls13HelloRetryTests
{
    [Fact]
    public async Task EcdsaCertificate_WithStatelessRetry_CompletesHandshake()
    {
        using X509Certificate2 serverCertificate = CreateEcdsaSelfSigned("CN=dtls-hrr-ecdsa");
        await RunHelloRetryHandshakeAsync(serverCertificate, requireClientCertificate: false);
    }

    [Fact]
    public async Task RsaCertificate_WithStatelessRetry_CompletesHandshake()
    {
        using X509Certificate2 serverCertificate = CreateRsaSelfSigned("CN=dtls-hrr-rsa");
        await RunHelloRetryHandshakeAsync(serverCertificate, requireClientCertificate: false);
    }

    [Fact]
    public async Task MutualAuth_WithStatelessRetry_CompletesHandshake()
    {
        using X509Certificate2 serverCertificate = CreateEcdsaSelfSigned("CN=dtls-hrr-mtls-srv");
        using X509Certificate2 clientCertificate = CreateEcdsaSelfSigned("CN=dtls-hrr-mtls-cli");
        await RunHelloRetryHandshakeAsync(
            serverCertificate, requireClientCertificate: true, clientCertificate);
    }

    private static async Task RunHelloRetryHandshakeAsync(
        X509Certificate2 serverCertificate,
        bool requireClientCertificate,
        X509Certificate2? clientCertificate = null)
    {
        (InMemoryDatagramTransport clientTransport, InMemoryDatagramTransport serverTransport) =
            InMemoryDatagramTransport.CreatePair();

        using CancellationTokenSource cts = new(TimeSpan.FromSeconds(15));
        using (clientTransport)
        using (serverTransport)
        {
            string serverThumbprint = serverCertificate.Thumbprint;
            string? clientThumbprint = clientCertificate?.Thumbprint;

            DtlsServer server = new(new DtlsServerOptions
            {
                MinimumVersion = DtlsProtocolVersion.Dtls13,
                MaximumVersion = DtlsProtocolVersion.Dtls13,
                ServerCertificate = serverCertificate,
                EnableStatelessRetry = true,
                RequireClientCertificate = requireClientCertificate,
                ClientCertificateValidation = clientThumbprint is null
                    ? null
                    : (presented, _, _) => string.Equals(
                        presented.Thumbprint, clientThumbprint, StringComparison.OrdinalIgnoreCase),
            });

            DtlsClientOptions clientOptions = new()
            {
                MinimumVersion = DtlsProtocolVersion.Dtls13,
                MaximumVersion = DtlsProtocolVersion.Dtls13,
                HandshakeTimeout = TimeSpan.FromSeconds(15),
                RemoteCertificateValidation = (presented, _, _) => string.Equals(
                    presented.Thumbprint, serverThumbprint, StringComparison.OrdinalIgnoreCase),
            };

            if (clientCertificate is not null)
            {
                clientOptions.ClientCertificates.Add(clientCertificate);
            }

            Task<DtlsConnection> serverTask = server.AcceptAsync(serverTransport, cts.Token);
            Task<DtlsConnection> clientTask = DtlsClient.ConnectAsync(
                clientTransport, clientOptions, cts.Token);

            DtlsConnection[] connections = await Task.WhenAll(serverTask, clientTask);
            using DtlsConnection serverConnection = connections[0];
            using DtlsConnection clientConnection = connections[1];

            Assert.Equal(DtlsProtocolVersion.Dtls13, serverConnection.NegotiatedVersion);
            Assert.Equal(DtlsProtocolVersion.Dtls13, clientConnection.NegotiatedVersion);

            await AssertEchoAsync(
                clientConnection, serverConnection, Bytes("hrr-hello"), cts.Token);
            await AssertEchoAsync(serverConnection, clientConnection, Bytes("hrr-back"), cts.Token);
        }
    }

    private static byte[] Bytes(string s) => Encoding.ASCII.GetBytes(s);

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

    private static X509Certificate2 CreateEcdsaSelfSigned(string subject)
    {
        using ECDsa key = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        CertificateRequest request = new(subject, key, HashAlgorithmName.SHA256);
        DateTimeOffset now = DateTimeOffset.UtcNow;
        return request.CreateSelfSigned(now.AddMinutes(-5), now.AddHours(1));
    }

    private static X509Certificate2 CreateRsaSelfSigned(string subject)
    {
        using RSA key = RSA.Create(2048);
        CertificateRequest request = new(
            subject, key, HashAlgorithmName.SHA256, RSASignaturePadding.Pss);
        DateTimeOffset now = DateTimeOffset.UtcNow;
        return request.CreateSelfSigned(now.AddMinutes(-5), now.AddHours(1));
    }
}

#pragma warning restore CA2025
