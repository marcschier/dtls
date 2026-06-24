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
/// End-to-end tests that drive the managed DTLS 1.3 handshake over a deterministic lossy
/// transport (seeded packet drop and duplication), exercising the RFC 9147 section 5.8
/// retransmission, the section 7 ACK of the final flight, and duplicate-flight suppression.
/// The handshake must still complete and exchange protected application data.
/// </summary>
public sealed class Dtls13LossyTransportTests
{
    private static readonly byte[] Identity = Encoding.ASCII.GetBytes("lossy-identity");

    private static readonly byte[] PresharedKey =
    {
        0x10, 0x20, 0x30, 0x40, 0x50, 0x60, 0x70, 0x80,
        0x90, 0xA0, 0xB0, 0xC0, 0xD0, 0xE0, 0xF0, 0x11,
    };

    [Theory]
    [InlineData(1)]
    [InlineData(2)]
    [InlineData(3)]
    [InlineData(5)]
    [InlineData(7)]
    [InlineData(11)]
    [InlineData(13)]
    [InlineData(17)]
    public async Task PskHandshake_OverLossyTransport_Completes(int seed)
    {
        await RunPskHandshakeAsync(seed, 0.3);
    }

    [Theory]
    [InlineData(2)]
    [InlineData(6)]
    [InlineData(10)]
    public async Task PskHandshake_OverHighLossTransport_Completes(int seed)
    {
        await RunPskHandshakeAsync(seed, 0.5);
    }

    [Theory]
    [InlineData(1)]
    [InlineData(3)]
    [InlineData(4)]
    [InlineData(6)]
    [InlineData(9)]
    [InlineData(12)]
    public async Task CertificateHandshake_OverLossyTransport_Completes(int seed)
    {
        using X509Certificate2 serverCertificate = CreateEcdsaSelfSigned("CN=dtls-lossy-cert");
        await RunCertificateHandshakeAsync(seed, serverCertificate);
    }

    private static async Task RunPskHandshakeAsync(int seed, double dropProbability)
    {
        (InMemoryDatagramTransport clientInner, InMemoryDatagramTransport serverInner) =
            InMemoryDatagramTransport.CreatePair();

        using LossyDatagramTransport clientTransport =
            new(clientInner, seed, dropProbability, 0.1);
        using LossyDatagramTransport serverTransport =
            new(serverInner, seed + 1000, dropProbability, 0.1);

        using CancellationTokenSource cts = new(TimeSpan.FromSeconds(30));

        DtlsServer server = new(new DtlsServerOptions
        {
            MinimumVersion = DtlsProtocolVersion.Dtls13,
            MaximumVersion = DtlsProtocolVersion.Dtls13,
            HandshakeRetransmissionTimeout = TimeSpan.FromMilliseconds(20),
            MaxHandshakeRetransmissions = 50,
            PskCallback = identity =>
                identity.Span.SequenceEqual(Identity) ? PresharedKey : ReadOnlyMemory<byte>.Empty,
        });

        DtlsClientOptions clientOptions = new()
        {
            MinimumVersion = DtlsProtocolVersion.Dtls13,
            MaximumVersion = DtlsProtocolVersion.Dtls13,
            HandshakeRetransmissionTimeout = TimeSpan.FromMilliseconds(20),
            MaxHandshakeRetransmissions = 50,
            PskCallback = _ => new PskCredential(Identity, PresharedKey),
        };

        Task<DtlsConnection> serverTask = server.AcceptAsync(serverTransport, cts.Token);
        Task<DtlsConnection> clientTask = DtlsClient.ConnectAsync(
            clientTransport, clientOptions, cts.Token);

        DtlsConnection[] connections = await Task.WhenAll(serverTask, clientTask);
        using DtlsConnection serverConnection = connections[0];
        using DtlsConnection clientConnection = connections[1];

        // Completing the handshake over a 30%-loss transport requires the retransmission, ACK,
        // and duplicate-suppression machinery to have worked end to end.
        Assert.Equal(DtlsProtocolVersion.Dtls13, serverConnection.NegotiatedVersion);
        Assert.Equal(DtlsProtocolVersion.Dtls13, clientConnection.NegotiatedVersion);
    }

    private static async Task RunCertificateHandshakeAsync(
        int seed,
        X509Certificate2 serverCertificate)
    {
        (InMemoryDatagramTransport clientInner, InMemoryDatagramTransport serverInner) =
            InMemoryDatagramTransport.CreatePair();

        using LossyDatagramTransport clientTransport = new(clientInner, seed, 0.3, 0.1);
        using LossyDatagramTransport serverTransport = new(serverInner, seed + 1000, 0.3, 0.1);

        using CancellationTokenSource cts = new(TimeSpan.FromSeconds(30));

        string serverThumbprint = serverCertificate.Thumbprint;

        DtlsServer server = new(new DtlsServerOptions
        {
            MinimumVersion = DtlsProtocolVersion.Dtls13,
            MaximumVersion = DtlsProtocolVersion.Dtls13,
            HandshakeRetransmissionTimeout = TimeSpan.FromMilliseconds(20),
            MaxHandshakeRetransmissions = 50,
            ServerCertificate = serverCertificate,
        });

        DtlsClientOptions clientOptions = new()
        {
            MinimumVersion = DtlsProtocolVersion.Dtls13,
            MaximumVersion = DtlsProtocolVersion.Dtls13,
            HandshakeRetransmissionTimeout = TimeSpan.FromMilliseconds(20),
            MaxHandshakeRetransmissions = 50,
            RemoteCertificateValidation = (presented, _, _) => string.Equals(
                presented.Thumbprint, serverThumbprint, StringComparison.OrdinalIgnoreCase),
        };

        Task<DtlsConnection> serverTask = server.AcceptAsync(serverTransport, cts.Token);
        Task<DtlsConnection> clientTask = DtlsClient.ConnectAsync(
            clientTransport, clientOptions, cts.Token);

        DtlsConnection[] connections = await Task.WhenAll(serverTask, clientTask);
        using DtlsConnection serverConnection = connections[0];
        using DtlsConnection clientConnection = connections[1];

        Assert.Equal(DtlsProtocolVersion.Dtls13, serverConnection.NegotiatedVersion);
        Assert.Equal(DtlsProtocolVersion.Dtls13, clientConnection.NegotiatedVersion);
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
