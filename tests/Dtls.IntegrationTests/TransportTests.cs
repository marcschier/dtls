using System;
using System.Net;
using System.Net.Sockets;
using System.Threading;
using System.Threading.Tasks;
using Dtls.Transport;
using Xunit;

namespace Dtls.IntegrationTests;

/// <summary>End-to-end tests for the datagram transport implementations.</summary>
public sealed class TransportTests
{
    [Fact]
    public async Task InMemory_RoundTrips_BothDirections()
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
            Assert.Equal(payload, buffer[..received]);

            byte[] reply = { 9, 8, 7 };
            await b.SendAsync(reply);
            int replyReceived = await a.ReceiveAsync(buffer);
            Assert.Equal(reply, buffer[..replyReceived]);
        }
    }

    [Fact]
    public async Task InMemory_PreservesDatagramBoundaries()
    {
        (InMemoryDatagramTransport a, InMemoryDatagramTransport b) =
            InMemoryDatagramTransport.CreatePair();
        using (a)
        using (b)
        {
            await a.SendAsync(new byte[] { 1, 1 });
            await a.SendAsync(new byte[] { 2, 2, 2 });

            byte[] buffer = new byte[16];
            int first = await b.ReceiveAsync(buffer);
            Assert.Equal(new byte[] { 1, 1 }, buffer[..first]);

            int second = await b.ReceiveAsync(buffer);
            Assert.Equal(new byte[] { 2, 2, 2 }, buffer[..second]);
        }
    }

    [Fact]
    public async Task Udp_Loopback_RoundTrips()
    {
        using Socket s1 = new(AddressFamily.InterNetwork, SocketType.Dgram, ProtocolType.Udp);
        using Socket s2 = new(AddressFamily.InterNetwork, SocketType.Dgram, ProtocolType.Udp);
        s1.Bind(new IPEndPoint(IPAddress.Loopback, 0));
        s2.Bind(new IPEndPoint(IPAddress.Loopback, 0));
        await s1.ConnectAsync((IPEndPoint)s2.LocalEndPoint!);
        await s2.ConnectAsync((IPEndPoint)s1.LocalEndPoint!);

        using UdpDatagramTransport t1 = new(s1, ownsSocket: false);
        using UdpDatagramTransport t2 = new(s2, ownsSocket: false);

        byte[] payload = { 10, 20, 30 };
        await t1.SendAsync(payload);

        byte[] buffer = new byte[2048];
        using CancellationTokenSource cts = new(TimeSpan.FromSeconds(5));
        int received = await t2.ReceiveAsync(buffer, cts.Token);
        Assert.Equal(payload, buffer[..received]);
    }
}
