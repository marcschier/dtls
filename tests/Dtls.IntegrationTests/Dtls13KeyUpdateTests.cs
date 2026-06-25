// Copyright (c) marcschier. All rights reserved.
// Licensed under the MIT License. See LICENSE in the project root for license information.

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
/// End-to-end tests for DTLS 1.3 post-handshake KeyUpdate (RFC 8446 section 4.6.3 / RFC 9147):
/// after a PSK handshake, each side rotates its application traffic keys (unsolicited and
/// peer-requested) and protected data continues to flow across the epoch changes.
/// </summary>
public sealed class Dtls13KeyUpdateTests
{
    private static readonly byte[] Identity = Encoding.ASCII.GetBytes("keyupdate-identity");

    private static readonly byte[] PresharedKey = new byte[]
    {
        0x10, 0x0F, 0x0E, 0x0D, 0x0C, 0x0B, 0x0A, 0x09,
        0x08, 0x07, 0x06, 0x05, 0x04, 0x03, 0x02, 0x01,
    };

    [Fact]
    public async Task KeyUpdate_UnsolicitedAndRequested_ContinuesProtectedExchange()
    {
        (InMemoryDatagramTransport clientTransport, InMemoryDatagramTransport serverTransport) =
            InMemoryDatagramTransport.CreatePair();

        using CancellationTokenSource cts = new(TimeSpan.FromSeconds(15));
        using (clientTransport)
        using (serverTransport)
        {
            DtlsServer server = new(ServerOptions());

            Task<DtlsConnection> serverTask = server.AcceptAsync(serverTransport, cts.Token);
            Task<DtlsConnection> clientTask = DtlsClient.ConnectAsync(
                clientTransport, ClientOptions(), cts.Token);

            DtlsConnection[] connections = await Task.WhenAll(serverTask, clientTask);
            using DtlsConnection serverConnection = connections[0];
            using DtlsConnection clientConnection = connections[1];

            // Baseline exchange before any key update.
            await AssertEchoAsync(clientConnection, serverConnection, Bytes("a0"), cts.Token);
            await AssertEchoAsync(serverConnection, clientConnection, Bytes("a1"), cts.Token);

            // Unsolicited client KeyUpdate, then send under the new client send keys.
            await clientConnection.UpdateKeyAsync(requestPeerUpdate: false, cts.Token);
            await AssertEchoAsync(clientConnection, serverConnection, Bytes("b"), cts.Token);

            // Unsolicited server KeyUpdate, then send under the new server send keys.
            await serverConnection.UpdateKeyAsync(requestPeerUpdate: false, cts.Token);
            await AssertEchoAsync(serverConnection, clientConnection, Bytes("c"), cts.Token);

            // Server requests the client to update. The server sends 'd' under its new keys; the
            // client processes the request (rotating its receive keys and queuing a response
            // KeyUpdate that rotates its send keys), then decrypts 'd'.
            await serverConnection.UpdateKeyAsync(requestPeerUpdate: true, cts.Token);
            await AssertEchoAsync(serverConnection, clientConnection, Bytes("d"), cts.Token);

            // The client's response KeyUpdate is delivered while the server reads the next
            // datagram, rotating the server's receive keys so 'e' decrypts.
            await AssertEchoAsync(clientConnection, serverConnection, Bytes("e"), cts.Token);

            // Final exchange both directions confirms the key state is consistent on both ends.
            await AssertEchoAsync(clientConnection, serverConnection, Bytes("f0"), cts.Token);
            await AssertEchoAsync(serverConnection, clientConnection, Bytes("f1"), cts.Token);
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

    private static DtlsServerOptions ServerOptions()
    {
        return new DtlsServerOptions
        {
            MinimumVersion = DtlsProtocolVersion.Dtls13,
            MaximumVersion = DtlsProtocolVersion.Dtls13,
            PskCallback = identity =>
                identity.Span.SequenceEqual(Identity)
                    ? PresharedKey
                    : ReadOnlyMemory<byte>.Empty,
        };
    }

    private static DtlsClientOptions ClientOptions()
    {
        return new DtlsClientOptions
        {
            MinimumVersion = DtlsProtocolVersion.Dtls13,
            MaximumVersion = DtlsProtocolVersion.Dtls13,
            HandshakeTimeout = TimeSpan.FromSeconds(15),
            PskCallback = _ => new PskCredential(Identity, PresharedKey),
        };
    }
}

#pragma warning restore CA2025
