// Copyright (c) marcschier. All rights reserved.
// Licensed under the MIT License. See LICENSE in the project root for license information.

using System;
using System.Net;
using System.Net.Sockets;
using System.Threading.Tasks;
using Dtls;
using Dtls.Transport;
using Xunit;

namespace Dtls.NetFxSmokeTests;

/// <summary>
/// Smoke tests that the netstandard2.0 build of the library loads and runs on .NET Framework 4.8.
/// The polyfilled value types (Span/Memory/ValueTask) and the datagram transports work at runtime,
/// while the cryptographic handshake degrades cleanly to
/// <see cref="PlatformNotSupportedException"/> (managed AEAD/ECDHE require .NET 8 or later).
/// </summary>
public sealed class Ns20CompatTests
{
    [Fact]
    public async Task InMemoryTransport_RoundTrips_ADatagram()
    {
        (InMemoryDatagramTransport a, InMemoryDatagramTransport b) =
            InMemoryDatagramTransport.CreatePair();
        using (a)
        using (b)
        {
            byte[] payload = { 1, 2, 3, 4, 5 };
            await a.SendAsync(payload);

            byte[] buffer = new byte[64];
            int received = await b.ReceiveAsync(buffer);

            Assert.Equal(payload.Length, received);
            Assert.Equal(payload, buffer.AsSpan(0, received).ToArray());
        }
    }

    [Fact]
    public async Task UdpTransport_RoundTrips_OverLoopback()
    {
        using Socket socketA =
            new(AddressFamily.InterNetwork, SocketType.Dgram, ProtocolType.Udp);
        using Socket socketB =
            new(AddressFamily.InterNetwork, SocketType.Dgram, ProtocolType.Udp);
        socketA.Bind(new IPEndPoint(IPAddress.Loopback, 0));
        socketB.Bind(new IPEndPoint(IPAddress.Loopback, 0));

        // UDP Connect only records the default peer for the datagram socket; it does not block
        // on a network handshake, so the async-blocking analyzers do not apply here.
#pragma warning disable CA1849, VSTHRD103
        socketA.Connect((IPEndPoint)socketB.LocalEndPoint);
        socketB.Connect((IPEndPoint)socketA.LocalEndPoint);
#pragma warning restore CA1849, VSTHRD103

        using var transportA = new UdpDatagramTransport(socketA, ownsSocket: false);
        using var transportB = new UdpDatagramTransport(socketB, ownsSocket: false);

        byte[] payload = { 9, 8, 7, 6 };
        await transportA.SendAsync(payload);

        byte[] buffer = new byte[64];
        int received = await transportB.ReceiveAsync(buffer);

        Assert.Equal(payload.Length, received);
        Assert.Equal(payload, buffer.AsSpan(0, received).ToArray());
    }

    [Fact]
    public async Task ClientHandshake_Throws_PlatformNotSupported()
    {
        (InMemoryDatagramTransport client, InMemoryDatagramTransport server) =
            InMemoryDatagramTransport.CreatePair();
        using (client)
        using (server)
        {
            DtlsClientOptions options = new();

            await Assert.ThrowsAsync<PlatformNotSupportedException>(
                async () => await DtlsClient.ConnectAsync(client, options));
        }
    }
}
