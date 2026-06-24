using System;
using System.Collections.Generic;
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
/// End-to-end tests that force a specific DTLS 1.3 cipher suite on both endpoints and verify
/// the managed handshake negotiates it and exchanges protected data in both directions. The
/// AES-256-GCM suite runs on every target framework; the AES-CCM suites run on .NET 8+.
/// </summary>
public sealed class Dtls13CipherSuiteHandshakeTests
{
    private static readonly byte[] Identity = Encoding.ASCII.GetBytes("test-identity");

    private static readonly byte[] PresharedKey = new byte[]
    {
        0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
        0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10,
    };

    public static IEnumerable<object[]> PskSuites()
    {
        // AES-256-GCM uses SHA-384 and is not offered for external-PSK (which fixes SHA-256),
        // so the PSK matrix covers the SHA-256 suites.
        yield return new object[] { DtlsCipherSuite.Aes128GcmSha256 };
#if NET8_0_OR_GREATER
        if (System.Security.Cryptography.AesCcm.IsSupported)
        {
            yield return new object[] { DtlsCipherSuite.Aes128CcmSha256 };
            yield return new object[] { DtlsCipherSuite.Aes128Ccm8Sha256 };
        }
#endif
    }

    public static IEnumerable<object[]> CertSuites()
    {
        yield return new object[] { DtlsCipherSuite.Aes128GcmSha256 };
        yield return new object[] { DtlsCipherSuite.Aes256GcmSha384 };
#if NET8_0_OR_GREATER
        if (System.Security.Cryptography.AesCcm.IsSupported)
        {
            yield return new object[] { DtlsCipherSuite.Aes128CcmSha256 };
            yield return new object[] { DtlsCipherSuite.Aes128Ccm8Sha256 };
        }
#endif
    }

    [Theory]
    [MemberData(nameof(PskSuites))]
    public async Task PskHandshake_ForcedSuite_NegotiatesAndExchangesData(DtlsCipherSuite suite)
    {
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
                CipherSuites = new[] { suite },
                PskCallback = identity =>
                    identity.Span.SequenceEqual(Identity)
                        ? PresharedKey
                        : ReadOnlyMemory<byte>.Empty,
            });

            DtlsClientOptions clientOptions = new()
            {
                MinimumVersion = DtlsProtocolVersion.Dtls13,
                MaximumVersion = DtlsProtocolVersion.Dtls13,
                HandshakeTimeout = TimeSpan.FromSeconds(10),
                CipherSuites = new[] { suite },
                PskCallback = _ => new PskCredential(Identity, PresharedKey),
            };

            Task<DtlsConnection> serverTask = server.AcceptAsync(serverTransport, cts.Token);
            Task<DtlsConnection> clientTask = DtlsClient.ConnectAsync(
                clientTransport, clientOptions, cts.Token);

            DtlsConnection[] connections = await Task.WhenAll(serverTask, clientTask);
            using DtlsConnection serverConnection = connections[0];
            using DtlsConnection clientConnection = connections[1];

            Assert.Equal(DtlsProtocolVersion.Dtls13, serverConnection.NegotiatedVersion);
            Assert.Equal(DtlsProtocolVersion.Dtls13, clientConnection.NegotiatedVersion);

            await AssertBidirectionalEchoAsync(clientConnection, serverConnection, cts.Token);
        }
    }

    [Theory]
    [MemberData(nameof(CertSuites))]
    public async Task CertHandshake_ForcedSuite_NegotiatesAndExchangesData(DtlsCipherSuite suite)
    {
        using X509Certificate2 certificate = CreateEcdsaSelfSigned();
        string thumbprint = certificate.Thumbprint;

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
                CipherSuites = new[] { suite },
                ServerCertificate = certificate,
            });

            DtlsClientOptions clientOptions = new()
            {
                MinimumVersion = DtlsProtocolVersion.Dtls13,
                MaximumVersion = DtlsProtocolVersion.Dtls13,
                HandshakeTimeout = TimeSpan.FromSeconds(10),
                CipherSuites = new[] { suite },
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

            await AssertBidirectionalEchoAsync(clientConnection, serverConnection, cts.Token);
        }
    }

#if NET8_0_OR_GREATER
    [Fact]
    public async Task CertHandshake_NoOverlappingSuite_FailsHandshake()
    {
        if (!System.Security.Cryptography.AesCcm.IsSupported)
        {
            return;
        }

        using X509Certificate2 certificate = CreateEcdsaSelfSigned();

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
                CipherSuites = new[] { DtlsCipherSuite.Aes128GcmSha256 },
                ServerCertificate = certificate,
            });

            DtlsClientOptions clientOptions = new()
            {
                MinimumVersion = DtlsProtocolVersion.Dtls13,
                MaximumVersion = DtlsProtocolVersion.Dtls13,
                HandshakeTimeout = TimeSpan.FromSeconds(2),
                CipherSuites = new[] { DtlsCipherSuite.Aes128CcmSha256 },
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
#endif

    private static async Task AssertBidirectionalEchoAsync(
        DtlsConnection clientConnection,
        DtlsConnection serverConnection,
        CancellationToken cancellationToken)
    {
        await AssertEchoAsync(clientConnection, serverConnection, Encoding.ASCII.GetBytes(
            "hello from the client"), cancellationToken);
        await AssertEchoAsync(serverConnection, clientConnection, Encoding.ASCII.GetBytes(
            "hello back from the server"), cancellationToken);

        // A single zero byte exercises the CCM-8 short-record padding path.
        await AssertEchoAsync(
            clientConnection, serverConnection, new byte[] { 0 }, cancellationToken);
        await AssertEchoAsync(serverConnection, clientConnection, new byte[] { 1, 2, 3, 4, 5 },
            cancellationToken);
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

    private static X509Certificate2 CreateEcdsaSelfSigned()
    {
        using ECDsa key = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        CertificateRequest request = new(
            "CN=dtls-test-ecdsa", key, HashAlgorithmName.SHA256);
        DateTimeOffset now = DateTimeOffset.UtcNow;
        return request.CreateSelfSigned(now.AddMinutes(-5), now.AddHours(1));
    }
}

#pragma warning restore CA2025
