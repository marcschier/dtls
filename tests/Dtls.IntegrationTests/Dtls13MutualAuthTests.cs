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
/// End-to-end tests for DTLS 1.3 mutual (client-certificate) authentication (RFC 8446 §4.3.2):
/// the server sends a CertificateRequest, the client answers with its Certificate and
/// CertificateVerify, and the server validates them before the connection is established.
/// </summary>
public sealed class Dtls13MutualAuthTests
{
    [Fact]
    public async Task EcdsaMutualAuth_FullHandshake_ExchangesProtectedData()
    {
        using X509Certificate2 serverCertificate = CreateEcdsaSelfSigned("CN=dtls-mutual-server");
        using X509Certificate2 clientCertificate = CreateEcdsaSelfSigned("CN=dtls-mutual-client");

        (InMemoryDatagramTransport clientTransport, InMemoryDatagramTransport serverTransport) =
            InMemoryDatagramTransport.CreatePair();

        using CancellationTokenSource cts = new(TimeSpan.FromSeconds(15));
        using (clientTransport)
        using (serverTransport)
        {
            string clientThumbprint = clientCertificate.Thumbprint;
            string serverThumbprint = serverCertificate.Thumbprint;

            DtlsServer server = new(new DtlsServerOptions
            {
                MinimumVersion = DtlsProtocolVersion.Dtls13,
                MaximumVersion = DtlsProtocolVersion.Dtls13,
                ServerCertificate = serverCertificate,
                RequireClientCertificate = true,
                ClientCertificateValidation = (presented, _, _) =>
                    string.Equals(
                        presented.Thumbprint, clientThumbprint, StringComparison.OrdinalIgnoreCase),
            });

            DtlsClientOptions clientOptions = new()
            {
                MinimumVersion = DtlsProtocolVersion.Dtls13,
                MaximumVersion = DtlsProtocolVersion.Dtls13,
                HandshakeTimeout = TimeSpan.FromSeconds(15),
                RemoteCertificateValidation = (presented, _, _) =>
                    string.Equals(
                        presented.Thumbprint, serverThumbprint, StringComparison.OrdinalIgnoreCase),
            };
            clientOptions.ClientCertificates.Add(clientCertificate);

            Task<DtlsConnection> serverTask = server.AcceptAsync(serverTransport, cts.Token);
            Task<DtlsConnection> clientTask = DtlsClient.ConnectAsync(
                clientTransport, clientOptions, cts.Token);

            DtlsConnection[] connections = await Task.WhenAll(serverTask, clientTask);
            using DtlsConnection serverConnection = connections[0];
            using DtlsConnection clientConnection = connections[1];

            Assert.Equal(DtlsProtocolVersion.Dtls13, serverConnection.NegotiatedVersion);
            Assert.Equal(DtlsProtocolVersion.Dtls13, clientConnection.NegotiatedVersion);

            await AssertEchoAsync(clientConnection, serverConnection, Bytes("mutual-hello"),
                cts.Token);
            await AssertEchoAsync(serverConnection, clientConnection, Bytes("mutual-back"),
                cts.Token);
        }
    }

    [Fact]
    public async Task RequiredClientCertificate_Absent_FailsHandshake()
    {
        using X509Certificate2 serverCertificate = CreateEcdsaSelfSigned("CN=dtls-mutual-server2");

        (InMemoryDatagramTransport clientTransport, InMemoryDatagramTransport serverTransport) =
            InMemoryDatagramTransport.CreatePair();

        using CancellationTokenSource cts = new(TimeSpan.FromSeconds(10));
        using (clientTransport)
        using (serverTransport)
        {
            DtlsServer server = new(new DtlsServerOptions
            {
                MinimumVersion = DtlsProtocolVersion.Dtls13,
                MaximumVersion = DtlsProtocolVersion.Dtls13,
                ServerCertificate = serverCertificate,
                RequireClientCertificate = true,
            });

            // The client offers no client certificate.
            DtlsClientOptions clientOptions = new()
            {
                MinimumVersion = DtlsProtocolVersion.Dtls13,
                MaximumVersion = DtlsProtocolVersion.Dtls13,
                HandshakeTimeout = TimeSpan.FromSeconds(5),
                RemoteCertificateValidation = (_, _, _) => true,
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
            Assert.True(serverTask.IsFaulted);
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
}

#pragma warning restore CA2025
