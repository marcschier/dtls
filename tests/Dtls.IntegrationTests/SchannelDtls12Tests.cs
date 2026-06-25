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
/// End-to-end self-interop tests for the Windows Schannel DTLS 1.2 backend: our Schannel
/// client and our Schannel server complete a real SSPI handshake over an in-memory transport
/// using a self-signed server certificate and then exchange protected application datagrams.
/// The whole test no-ops on non-Windows hosts because Schannel is only available there.
/// </summary>
public sealed class SchannelDtls12Tests
{
    [Fact]
    public async Task EcdsaCertificate_Dtls12SelfInterop_ExchangesProtectedData()
    {
        if (!OperatingSystem.IsWindows())
        {
            return;
        }

        using X509Certificate2 certificate = CreateSchannelUsableEcdsaCertificate();
        await RunSelfInteropAsync(certificate);
    }

    [Fact]
    public async Task RsaCertificate_Dtls12SelfInterop_ExchangesProtectedData()
    {
        if (!OperatingSystem.IsWindows())
        {
            return;
        }

        using X509Certificate2 certificate = CreateSchannelUsableRsaCertificate();
        await RunSelfInteropAsync(certificate);
    }

    private static async Task RunSelfInteropAsync(X509Certificate2 certificate)
    {
        string thumbprint = certificate.Thumbprint;

        (InMemoryDatagramTransport clientTransport, InMemoryDatagramTransport serverTransport) =
            InMemoryDatagramTransport.CreatePair();

        using CancellationTokenSource cts = new(TimeSpan.FromSeconds(15));
        using (clientTransport)
        using (serverTransport)
        {
            DtlsServer server = new(new DtlsServerOptions
            {
                MinimumVersion = DtlsProtocolVersion.Dtls12,
                MaximumVersion = DtlsProtocolVersion.Dtls12,
                ServerCertificate = certificate,
                HandshakeTimeout = TimeSpan.FromSeconds(15),
            });

            DtlsClientOptions clientOptions = new()
            {
                MinimumVersion = DtlsProtocolVersion.Dtls12,
                MaximumVersion = DtlsProtocolVersion.Dtls12,
                TargetHost = "localhost",
                HandshakeTimeout = TimeSpan.FromSeconds(15),
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
                "hello from the schannel client"), cts.Token);
            await AssertEchoAsync(serverConnection, clientConnection, Encoding.ASCII.GetBytes(
                "hello back from the schannel server"), cts.Token);
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

    private static X509Certificate2 CreateSchannelUsableEcdsaCertificate()
    {
        using ECDsa key = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        CertificateRequest request = new(
            "CN=dtls-schannel-ecdsa", key, HashAlgorithmName.SHA256);
        DateTimeOffset now = DateTimeOffset.UtcNow;
        using X509Certificate2 ephemeral =
            request.CreateSelfSigned(now.AddMinutes(-5), now.AddHours(1));
        return MakeSchannelUsable(ephemeral);
    }

    private static X509Certificate2 CreateSchannelUsableRsaCertificate()
    {
        using RSA key = RSA.Create(2048);
        CertificateRequest request = new(
            "CN=dtls-schannel-rsa", key, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        DateTimeOffset now = DateTimeOffset.UtcNow;
        using X509Certificate2 ephemeral =
            request.CreateSelfSigned(now.AddMinutes(-5), now.AddHours(1));
        return MakeSchannelUsable(ephemeral);
    }

    private static X509Certificate2 MakeSchannelUsable(X509Certificate2 ephemeral)
    {
        // The ephemeral, in-memory private key produced by CreateSelfSigned is not accessible
        // to Schannel during the handshake. Round-trip through a PFX and load it with a
        // persisted key set so the SSP can find and use the private key.
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
