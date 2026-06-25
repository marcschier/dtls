// Copyright (c) marcschier. All rights reserved.
// Licensed under the MIT License. See LICENSE in the project root for license information.

using System;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using Dtls.Protocol.V12.Handshake;
using Dtls.Protocol.V13;
using Dtls.Protocol.V13.Handshake;
using Dtls.Transport;
using Xunit;

// CA2025: the in-memory transports are always awaited (via Task.WhenAll) before the enclosing
// 'using' disposes them, so the handshake tasks never outlive the disposable instances.
// VSTHRD003: the echo helper awaits the client/server handshake tasks that were started earlier in
// the calling test method; there is no foreign synchronization context.
#pragma warning disable CA2025
#pragma warning disable VSTHRD003

namespace Dtls.IntegrationTests;

/// <summary>
/// Cross-implementation interop tests between the managed DTLS 1.2 engine and the native Windows
/// Schannel DTLS 1.2 backend (the wire-correctness gate, RFC 6347 / RFC 5246). On Windows the
/// public <see cref="DtlsServer"/>/<see cref="DtlsClient"/> route a DTLS 1.2 handshake to the
/// Schannel backend; the managed engine is driven directly on the opposing endpoint. Both
/// directions are exercised with certificate authentication (Schannel does not expose external
/// PSK). The whole test no-ops off Windows, where Schannel is unavailable.
/// </summary>
public sealed class Dtls12ManagedSchannelInteropTests
{
    [Fact]
    public async Task ManagedClient_SchannelServer_Ecdsa_Interops()
    {
        if (!OperatingSystem.IsWindows())
        {
            return;
        }

        using X509Certificate2 certificate = CreateSchannelUsableEcdsaCertificate();
        await ManagedClientAgainstSchannelServerAsync(certificate);
    }

    [Fact]
    public async Task ManagedClient_SchannelServer_Rsa_Interops()
    {
        if (!OperatingSystem.IsWindows())
        {
            return;
        }

        using X509Certificate2 certificate = CreateSchannelUsableRsaCertificate();
        await ManagedClientAgainstSchannelServerAsync(certificate);
    }

    [Fact]
    public async Task SchannelClient_ManagedServer_Ecdsa_Interops()
    {
        if (!OperatingSystem.IsWindows())
        {
            return;
        }

        using X509Certificate2 certificate = CreateEcdsaCertificate();
        await SchannelClientAgainstManagedServerAsync(certificate);
    }

    private static async Task ManagedClientAgainstSchannelServerAsync(X509Certificate2 certificate)
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
                RemoteCertificateValidation = (presented, _, _) =>
                    string.Equals(
                        presented.Thumbprint, thumbprint, StringComparison.OrdinalIgnoreCase),
            };

            Task<DtlsConnection> serverTask = server.AcceptAsync(serverTransport, cts.Token);
            Task<DtlsConnection> clientTask = Dtls12ClientHandshake.RunAsync(
                clientTransport, clientOptions, cts.Token);

            await RunEchoAsync(serverTask, clientTask, cts.Token);
        }
    }

    private static async Task SchannelClientAgainstManagedServerAsync(X509Certificate2 certificate)
    {
        string thumbprint = certificate.Thumbprint;

        (InMemoryDatagramTransport clientTransport, InMemoryDatagramTransport serverTransport) =
            InMemoryDatagramTransport.CreatePair();

        using CancellationTokenSource cts = new(TimeSpan.FromSeconds(20));
        using (clientTransport)
        using (serverTransport)
        {
            DtlsServerOptions serverOptions = new()
            {
                MinimumVersion = DtlsProtocolVersion.Dtls12,
                MaximumVersion = DtlsProtocolVersion.Dtls12,
                ServerCertificate = certificate,
                HandshakeTimeout = TimeSpan.FromSeconds(20),
            };

            DtlsClientOptions clientOptions = new()
            {
                MinimumVersion = DtlsProtocolVersion.Dtls12,
                MaximumVersion = DtlsProtocolVersion.Dtls12,
                TargetHost = "localhost",
                RemoteCertificateValidation = (presented, _, _) =>
                    string.Equals(
                        presented.Thumbprint, thumbprint, StringComparison.OrdinalIgnoreCase),
                HandshakeTimeout = TimeSpan.FromSeconds(20),
            };

            Task<DtlsConnection> serverTask = AcceptManagedAsync(
                serverTransport, serverOptions, cts.Token);
            Task<DtlsConnection> clientTask = DtlsClient.ConnectAsync(
                clientTransport, clientOptions, cts.Token);

            await RunEchoAsync(serverTask, clientTask, cts.Token);
        }
    }

    // Mirrors DtlsServer's initial-ClientHello reassembly: Schannel may fragment its DTLS handshake
    // messages, so the first ClientHello may span several datagrams and must be reassembled into a
    // single plaintext record before the managed server engine consumes it.
    private static async Task<DtlsConnection> AcceptManagedAsync(
        InMemoryDatagramTransport transport,
        DtlsServerOptions options,
        CancellationToken cancellationToken)
    {
        HandshakeReassembler reassembler =
            new(options.MaxHandshakeMessageSize, firstSequence: 0);
        byte[] buffer = new byte[transport.MaxDatagramSize];
        while (true)
        {
            int received = await transport.ReceiveAsync(buffer, cancellationToken);
            if (received == 0)
            {
                throw new DtlsException("The peer closed the transport before the ClientHello.");
            }

            Dtls13HandshakeFlight.OfferPlaintext(buffer.AsSpan(0, received), reassembler);
            if (reassembler.TryReadNext(
                out HandshakeType type, out byte[] body, out ushort sequence))
            {
                Assert.Equal(HandshakeType.ClientHello, type);
                byte[] message = HandshakeMessage.Serialize(type, sequence, body);
                byte[] initialDatagram = Dtls13PlaintextRecord.Encode(
                    Dtls13PlaintextRecord.HandshakeContentType, 0, 0, message);
                return await Dtls12ServerHandshake.RunAsync(
                    transport, options, initialDatagram, cancellationToken);
            }
        }
    }

    private static async Task RunEchoAsync(
        Task<DtlsConnection> serverTask,
        Task<DtlsConnection> clientTask,
        CancellationToken cancellationToken)
    {
        DtlsConnection[] connections = await Task.WhenAll(serverTask, clientTask);
        using DtlsConnection serverConnection = connections[0];
        using DtlsConnection clientConnection = connections[1];

        Assert.Equal(DtlsProtocolVersion.Dtls12, serverConnection.NegotiatedVersion);
        Assert.Equal(DtlsProtocolVersion.Dtls12, clientConnection.NegotiatedVersion);

        await AssertEchoAsync(clientConnection, serverConnection, Encoding.ASCII.GetBytes(
            "managed/schannel interop, client to server"), cancellationToken);
        await AssertEchoAsync(serverConnection, clientConnection, Encoding.ASCII.GetBytes(
            "managed/schannel interop, server to client"), cancellationToken);
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

    private static X509Certificate2 CreateEcdsaCertificate()
    {
        using ECDsa key = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        CertificateRequest request = new(
            "CN=dtls12-managed-schannel", key, HashAlgorithmName.SHA256);
        DateTimeOffset now = DateTimeOffset.UtcNow;
        return request.CreateSelfSigned(now.AddMinutes(-5), now.AddHours(1));
    }

    private static X509Certificate2 CreateSchannelUsableEcdsaCertificate()
    {
        using X509Certificate2 ephemeral = CreateEcdsaCertificate();
        return MakeSchannelUsable(ephemeral);
    }

    private static X509Certificate2 CreateSchannelUsableRsaCertificate()
    {
        using RSA key = RSA.Create(2048);
        CertificateRequest request = new(
            "CN=dtls12-managed-schannel", key, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        DateTimeOffset now = DateTimeOffset.UtcNow;
        using X509Certificate2 ephemeral =
            request.CreateSelfSigned(now.AddMinutes(-5), now.AddHours(1));
        return MakeSchannelUsable(ephemeral);
    }

    private static X509Certificate2 MakeSchannelUsable(X509Certificate2 ephemeral)
    {
        // The ephemeral in-memory private key is not accessible to Schannel during the handshake;
        // round-trip through a PFX with a persisted key set so the SSP can find the private key.
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
#pragma warning restore VSTHRD003
