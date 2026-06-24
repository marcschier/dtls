using System;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using Dtls;
using Dtls.Transport;
using Xunit;

// CA2025: the in-memory transports are always awaited before the enclosing 'using' disposes them.
#pragma warning disable CA2025

namespace Dtls.IntegrationTests;

/// <summary>
/// End-to-end tests for DTLS 1.3 Connection ID negotiation (RFC 9146): when both peers enable
/// CIDs, the negotiated identifiers are carried on every protected record (the CID is part of the
/// AEAD additional data, so a wrong CID would fail decryption). Also covers CID surviving a
/// KeyUpdate and the asymmetric case where only one side requests a CID.
/// </summary>
public sealed class Dtls13ConnectionIdTests
{
    private static readonly byte[] Identity = Encoding.ASCII.GetBytes("cid-identity");

    private static readonly byte[] PresharedKey = new byte[]
    {
        0xA0, 0xA1, 0xA2, 0xA3, 0xA4, 0xA5, 0xA6, 0xA7,
        0xA8, 0xA9, 0xAA, 0xAB, 0xAC, 0xAD, 0xAE, 0xAF,
    };

    [Fact]
    public async Task ConnectionId_BothEnabled_ExchangesProtectedDataAcrossKeyUpdate()
    {
        (DtlsConnection client, DtlsConnection server, IDisposable scope) =
            await HandshakeAsync(clientCid: true, serverCid: true);

        using (scope)
        using (client)
        using (server)
        {
            using CancellationTokenSource cts = new(TimeSpan.FromSeconds(15));

            await AssertEchoAsync(client, server, Encoding.ASCII.GetBytes("with-cid"), cts.Token);
            await AssertEchoAsync(server, client, Encoding.ASCII.GetBytes("cid-back"), cts.Token);

            // CID configuration must survive a key update (the rebuilt receive protector keeps the
            // negotiated CID length).
            await client.UpdateKeyAsync(requestPeerUpdate: false, cts.Token);
            await AssertEchoAsync(client, server, Encoding.ASCII.GetBytes("after-ku"), cts.Token);
        }
    }

    [Fact]
    public async Task ConnectionId_OnlyClientRequests_FallsBackToNoCid()
    {
        (DtlsConnection client, DtlsConnection server, IDisposable scope) =
            await HandshakeAsync(clientCid: true, serverCid: false);

        using (scope)
        using (client)
        using (server)
        {
            using CancellationTokenSource cts = new(TimeSpan.FromSeconds(15));
            await AssertEchoAsync(client, server, Encoding.ASCII.GetBytes("no-cid"), cts.Token);
            await AssertEchoAsync(server, client, Encoding.ASCII.GetBytes("still-ok"), cts.Token);
        }
    }

    private static async Task<(DtlsConnection Client, DtlsConnection Server, IDisposable Scope)>
        HandshakeAsync(bool clientCid, bool serverCid)
    {
        (InMemoryDatagramTransport clientTransport, InMemoryDatagramTransport serverTransport) =
            InMemoryDatagramTransport.CreatePair();

        CancellationTokenSource cts = new(TimeSpan.FromSeconds(15));
        DtlsServer server = new(new DtlsServerOptions
        {
            MinimumVersion = DtlsProtocolVersion.Dtls13,
            MaximumVersion = DtlsProtocolVersion.Dtls13,
            UseConnectionId = serverCid,
            PskCallback = identity =>
                identity.Span.SequenceEqual(Identity) ? PresharedKey : ReadOnlyMemory<byte>.Empty,
        });

        Task<DtlsConnection> serverTask = server.AcceptAsync(serverTransport, cts.Token);
        Task<DtlsConnection> clientTask = DtlsClient.ConnectAsync(
            clientTransport,
            new DtlsClientOptions
            {
                MinimumVersion = DtlsProtocolVersion.Dtls13,
                MaximumVersion = DtlsProtocolVersion.Dtls13,
                UseConnectionId = clientCid,
                PskCallback = _ => new PskCredential(Identity, PresharedKey),
            },
            cts.Token);

        DtlsConnection[] connections = await Task.WhenAll(serverTask, clientTask);
        Assert.Equal(DtlsProtocolVersion.Dtls13, connections[0].NegotiatedVersion);

        IDisposable scope = new TransportScope(clientTransport, serverTransport, cts);
        return (connections[1], connections[0], scope);
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

    private sealed class TransportScope : IDisposable
    {
        private readonly IDisposable _client;
        private readonly IDisposable _server;
        private readonly IDisposable _cts;

        public TransportScope(IDisposable client, IDisposable server, IDisposable cts)
        {
            _client = client;
            _server = server;
            _cts = cts;
        }

        public void Dispose()
        {
            _client.Dispose();
            _server.Dispose();
            _cts.Dispose();
        }
    }
}

#pragma warning restore CA2025
