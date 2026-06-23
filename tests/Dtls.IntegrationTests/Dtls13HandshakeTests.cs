using System;
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
/// End-to-end tests for the managed DTLS 1.3 external-PSK + ECDHE (psk_dhe_ke) handshake:
/// a real client and server complete the handshake over an in-memory transport and then
/// exchange protected application datagrams in both directions.
/// </summary>
public sealed class Dtls13HandshakeTests
{
    private static readonly byte[] Identity = Encoding.ASCII.GetBytes("test-identity");

    private static readonly byte[] PresharedKey = new byte[]
    {
        0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
        0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10,
    };

    [Fact]
    public async Task PskDheKe_FullHandshake_ExchangesProtectedData()
    {
        (InMemoryDatagramTransport clientTransport, InMemoryDatagramTransport serverTransport) =
            InMemoryDatagramTransport.CreatePair();

        using CancellationTokenSource cts = new(TimeSpan.FromSeconds(10));
        using (clientTransport)
        using (serverTransport)
        {
            DtlsServer server = new(ServerOptions(PresharedKey));

            Task<DtlsConnection> serverTask = server.AcceptAsync(serverTransport, cts.Token);
            Task<DtlsConnection> clientTask = DtlsClient.ConnectAsync(
                clientTransport, ClientOptions(PresharedKey), cts.Token);

            DtlsConnection[] connections = await Task.WhenAll(serverTask, clientTask);
            using DtlsConnection serverConnection = connections[0];
            using DtlsConnection clientConnection = connections[1];

            Assert.Equal(DtlsProtocolVersion.Dtls13, serverConnection.NegotiatedVersion);
            Assert.Equal(DtlsProtocolVersion.Dtls13, clientConnection.NegotiatedVersion);

            await AssertEchoAsync(clientConnection, serverConnection, Encoding.ASCII.GetBytes(
                "hello from the client"), cts.Token);
            await AssertEchoAsync(serverConnection, clientConnection, Encoding.ASCII.GetBytes(
                "hello back from the server"), cts.Token);

            // Multiple datagrams in sequence keep working (sequence numbers advance).
            await AssertEchoAsync(clientConnection, serverConnection, new byte[] { 0, 1, 2, 3, 4 },
                cts.Token);
        }
    }

    [Fact]
    public async Task PskDheKe_WrongClientKey_FailsHandshake()
    {
        (InMemoryDatagramTransport clientTransport, InMemoryDatagramTransport serverTransport) =
            InMemoryDatagramTransport.CreatePair();

        using CancellationTokenSource cts = new(TimeSpan.FromSeconds(10));
        using (clientTransport)
        using (serverTransport)
        {
            DtlsServer server = new(ServerOptions(PresharedKey));

            byte[] wrongKey = (byte[])PresharedKey.Clone();
            wrongKey[0] ^= 0xFF;

            Task<DtlsConnection> serverTask = server.AcceptAsync(serverTransport, cts.Token);
            Task<DtlsConnection> clientTask = DtlsClient.ConnectAsync(
                clientTransport, ClientOptions(wrongKey, TimeSpan.FromSeconds(2)), cts.Token);

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

    private static DtlsServerOptions ServerOptions(byte[] key)
    {
        return new DtlsServerOptions
        {
            MinimumVersion = DtlsProtocolVersion.Dtls13,
            MaximumVersion = DtlsProtocolVersion.Dtls13,
            PskCallback = identity =>
                identity.Span.SequenceEqual(Identity)
                    ? key
                    : ReadOnlyMemory<byte>.Empty,
        };
    }

    private static DtlsClientOptions ClientOptions(byte[] key, TimeSpan? handshakeTimeout = null)
    {
        return new DtlsClientOptions
        {
            MinimumVersion = DtlsProtocolVersion.Dtls13,
            MaximumVersion = DtlsProtocolVersion.Dtls13,
            HandshakeTimeout = handshakeTimeout ?? TimeSpan.FromSeconds(10),
            PskCallback = _ => new PskCredential(Identity, key),
        };
    }
}

#pragma warning restore CA2025
