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
// CA2000: the optional lossy wrapper is disposed by the enclosing 'using' (it forwards Dispose to
// the inner transport), but the conditional creation defeats the analyzer's flow tracking.
#pragma warning disable CA2000, CA2025

namespace Dtls.IntegrationTests;

/// <summary>
/// End-to-end tests for managed DTLS 1.3 handshake message fragmentation/reassembly
/// (RFC 9147 section 5.5): handshakes run over an in-memory transport with a small
/// MaxDatagramSize so the (large) Certificate flight is split into fragment records across
/// datagrams and reassembled, including combined with packet loss.
/// </summary>
public sealed class Dtls13FragmentationTests
{
    private const int SmallMtu = 512;
    private const int TinyMtu = 96;

    private static readonly byte[] Identity = Encoding.ASCII.GetBytes("frag-identity");

    private static readonly byte[] PresharedKey =
    {
        0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88,
        0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x00,
    };

    [Fact]
    public async Task CertificateHandshake_SmallMtu_FragmentsAndCompletes()
    {
        // RSA-3072 produces a Certificate message well over the 512-byte MTU, forcing the server
        // flight to fragment across several datagrams.
        using X509Certificate2 serverCertificate = CreateRsaSelfSigned("CN=dtls-frag-rsa", 3072);
        await RunCertificateHandshakeAsync(
            serverCertificate, SmallMtu, dropProbability: 0, seed: 0, enableStatelessRetry: false);
    }

    [Theory]
    [InlineData(1)]
    [InlineData(2)]
    [InlineData(5)]
    [InlineData(8)]
    public async Task CertificateHandshake_SmallMtuAndLossy_Completes(int seed)
    {
        using X509Certificate2 serverCertificate = CreateRsaSelfSigned("CN=dtls-frag-lossy", 3072);
        await RunCertificateHandshakeAsync(
            serverCertificate, SmallMtu, dropProbability: 0.25, seed, enableStatelessRetry: false);
    }

    [Fact]
    public async Task MutualAuth_SmallMtu_FragmentsBothDirections()
    {
        // Both certificates fragment, so the server flight and the client auth flight are split.
        using X509Certificate2 serverCertificate = CreateRsaSelfSigned("CN=dtls-frag-mtls-s", 3072);
        using X509Certificate2 clientCertificate = CreateRsaSelfSigned("CN=dtls-frag-mtls-c", 3072);
        await RunCertificateHandshakeAsync(
            serverCertificate, SmallMtu, dropProbability: 0, seed: 0,
            enableStatelessRetry: false, clientCertificate);
    }

    [Fact]
    public async Task CertificateHandshake_TinyMtu_FragmentsHellosAndFlight()
    {
        // A 96-byte MTU is below the ClientHello/ServerHello sizes, so the plaintext hellos
        // fragment (and reassemble at the routing layer / client) in addition to the Certificate.
        using X509Certificate2 serverCertificate = CreateRsaSelfSigned("CN=dtls-frag-tiny", 3072);
        await RunCertificateHandshakeAsync(
            serverCertificate, TinyMtu, dropProbability: 0, seed: 0, enableStatelessRetry: false);
    }

    [Fact]
    public async Task HelloRetry_TinyMtu_FragmentsEveryFlight()
    {
        // Stateless retry at a 96-byte MTU fragments ClientHello1, the HelloRetryRequest,
        // ClientHello2, the ServerHello, and the Certificate flight.
        using X509Certificate2 serverCertificate = CreateRsaSelfSigned("CN=dtls-frag-hrr", 3072);
        await RunCertificateHandshakeAsync(
            serverCertificate, TinyMtu, dropProbability: 0, seed: 0, enableStatelessRetry: true);
    }

    [Theory]
    [InlineData(1)]
    [InlineData(3)]
    public async Task CertificateHandshake_TinyMtuAndLossy_Completes(int seed)
    {
        using X509Certificate2 serverCertificate = CreateRsaSelfSigned("CN=dtls-frag-tl", 3072);
        await RunCertificateHandshakeAsync(
            serverCertificate, TinyMtu, dropProbability: 0.2, seed, enableStatelessRetry: false);
    }

    [Fact]
    public async Task PskHandshake_SmallMtu_Completes()
    {
        (InMemoryDatagramTransport clientInner, InMemoryDatagramTransport serverInner) =
            InMemoryDatagramTransport.CreatePair(SmallMtu);

        using CancellationTokenSource cts = new(TimeSpan.FromSeconds(15));
        using (clientInner)
        using (serverInner)
        {
            DtlsServer server = new(new DtlsServerOptions
            {
                MinimumVersion = DtlsProtocolVersion.Dtls13,
                MaximumVersion = DtlsProtocolVersion.Dtls13,
                PskCallback = identity =>
                    identity.Span.SequenceEqual(Identity)
                        ? PresharedKey
                        : ReadOnlyMemory<byte>.Empty,
            });

            DtlsClientOptions clientOptions = new()
            {
                MinimumVersion = DtlsProtocolVersion.Dtls13,
                MaximumVersion = DtlsProtocolVersion.Dtls13,
                PskCallback = _ => new PskCredential(Identity, PresharedKey),
            };

            Task<DtlsConnection> serverTask = server.AcceptAsync(serverInner, cts.Token);
            Task<DtlsConnection> clientTask = DtlsClient.ConnectAsync(
                clientInner, clientOptions, cts.Token);

            DtlsConnection[] connections = await Task.WhenAll(serverTask, clientTask);
            using DtlsConnection serverConnection = connections[0];
            using DtlsConnection clientConnection = connections[1];

            Assert.Equal(DtlsProtocolVersion.Dtls13, serverConnection.NegotiatedVersion);
            Assert.Equal(DtlsProtocolVersion.Dtls13, clientConnection.NegotiatedVersion);
        }
    }

    private static async Task RunCertificateHandshakeAsync(
        X509Certificate2 serverCertificate,
        int mtu,
        double dropProbability,
        int seed,
        bool enableStatelessRetry,
        X509Certificate2? clientCertificate = null)
    {
        (InMemoryDatagramTransport clientInner, InMemoryDatagramTransport serverInner) =
            InMemoryDatagramTransport.CreatePair(mtu);

        IDatagramTransport clientTransport = dropProbability > 0
            ? new LossyDatagramTransport(clientInner, seed, dropProbability, 0.1)
            : clientInner;
        IDatagramTransport serverTransport = dropProbability > 0
            ? new LossyDatagramTransport(serverInner, seed + 1000, dropProbability, 0.1)
            : serverInner;

        using CancellationTokenSource cts = new(TimeSpan.FromSeconds(30));
        using (clientTransport)
        using (serverTransport)
        {
            string serverThumbprint = serverCertificate.Thumbprint;
            string? clientThumbprint = clientCertificate?.Thumbprint;

            DtlsServer server = new(new DtlsServerOptions
            {
                MinimumVersion = DtlsProtocolVersion.Dtls13,
                MaximumVersion = DtlsProtocolVersion.Dtls13,
                HandshakeRetransmissionTimeout = TimeSpan.FromMilliseconds(20),
                MaxHandshakeRetransmissions = 60,
                ServerCertificate = serverCertificate,
                EnableStatelessRetry = enableStatelessRetry,
                RequireClientCertificate = clientCertificate is not null,
                ClientCertificateValidation = clientThumbprint is null
                    ? null
                    : (presented, _, _) => string.Equals(
                        presented.Thumbprint, clientThumbprint, StringComparison.OrdinalIgnoreCase),
            });

            DtlsClientOptions clientOptions = new()
            {
                MinimumVersion = DtlsProtocolVersion.Dtls13,
                MaximumVersion = DtlsProtocolVersion.Dtls13,
                HandshakeRetransmissionTimeout = TimeSpan.FromMilliseconds(20),
                MaxHandshakeRetransmissions = 60,
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
        }
    }

    private static X509Certificate2 CreateRsaSelfSigned(string subject, int keySize)
    {
        using RSA key = RSA.Create(keySize);
        CertificateRequest request = new(
            subject, key, HashAlgorithmName.SHA256, RSASignaturePadding.Pss);
        DateTimeOffset now = DateTimeOffset.UtcNow;
        return request.CreateSelfSigned(now.AddMinutes(-5), now.AddHours(1));
    }
}

#pragma warning restore CA2000, CA2025
