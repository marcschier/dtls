// Copyright (c) marcschier. All rights reserved.
// Licensed under the MIT License. See LICENSE in the project root for license information.

using System;
using System.Globalization;
using System.Net;
using System.Net.Sockets;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using Dtls;
using Dtls.Transport;

return await MainAsync(args);

static async Task<int> MainAsync(string[] arguments)
{
    try
    {
        (int port, bool selfTest) = ParseArgs(arguments);
        if (selfTest)
        {
            await RunSelfTestAsync();
            Console.WriteLine("selftest: OK");
            return 0;
        }

        return await RunServerAsync(port);
    }
    catch (Exception ex)
    {
        await Console.Error.WriteLineAsync("error: " + ex.Message);
        return 1;
    }
}

static (int Port, bool SelfTest) ParseArgs(string[] arguments)
{
    int port = 49555;
    bool selfTest = false;

    for (int index = 0; index < arguments.Length; index++)
    {
        string argument = arguments[index];
        if (StringComparer.Ordinal.Equals(argument, "--selftest"))
        {
            selfTest = true;
            continue;
        }

        if (StringComparer.Ordinal.Equals(argument, "--port"))
        {
            port = ParseRequiredPort(arguments, ref index);
            continue;
        }

        throw new ArgumentException("Unknown argument: " + argument);
    }

    return (port, selfTest);
}

static int ParseRequiredPort(string[] arguments, ref int index)
{
    if (index + 1 >= arguments.Length)
    {
        throw new ArgumentException("--port requires a value.");
    }

    string value = arguments[++index];
    bool parsed = int.TryParse(
        value,
        NumberStyles.Integer,
        CultureInfo.InvariantCulture,
        out int port);

    if (!parsed || port < IPEndPoint.MinPort || port > IPEndPoint.MaxPort)
    {
        throw new ArgumentException("Invalid port: " + value);
    }

    return port;
}

static async Task RunSelfTestAsync()
{
    (InMemoryDatagramTransport endpointA, InMemoryDatagramTransport endpointB) =
        InMemoryDatagramTransport.CreatePair();

    using (endpointA)
    using (endpointB)
    {
        await VerifyDatagramAsync(endpointA, endpointB, "server to client");
        await VerifyDatagramAsync(endpointB, endpointA, "client to server");
        await VerifyDatagramAsync(endpointA, endpointB, "final echo");
    }
}

static async Task VerifyDatagramAsync(
    IDatagramTransport sender,
    IDatagramTransport receiver,
    string text)
{
    byte[] expected = Encoding.UTF8.GetBytes(text);
    byte[] received = new byte[expected.Length + 8];

    await sender.SendAsync(expected, CancellationToken.None);
    int receivedLength = await receiver.ReceiveAsync(received, CancellationToken.None);

    if (receivedLength != expected.Length)
    {
        string expectedLength = expected.Length.ToString(CultureInfo.InvariantCulture);
        string actualLength = receivedLength.ToString(CultureInfo.InvariantCulture);
        throw new InvalidOperationException(
            "Expected " + expectedLength + " bytes but received " + actualLength + ".");
    }

    if (!received.AsSpan(0, receivedLength).SequenceEqual(expected))
    {
        throw new InvalidOperationException("Datagram payload changed during round-trip.");
    }
}

static async Task<int> RunServerAsync(int port)
{
    Console.WriteLine(
        "DTLS echo server sample binding UDP 127.0.0.1:"
        + port.ToString(CultureInfo.InvariantCulture)
        + ".");
    Console.WriteLine("The DTLS server handshake is under construction.");

    using Socket socket = new(AddressFamily.InterNetwork, SocketType.Dgram, ProtocolType.Udp);
    socket.Bind(new IPEndPoint(IPAddress.Loopback, port));
    await socket.ConnectAsync(new IPEndPoint(IPAddress.Loopback, port));

    using UdpDatagramTransport transport = new(socket, ownsSocket: false);
    using CancellationTokenSource timeout = new(TimeSpan.FromMilliseconds(250));

    DtlsServerOptions options = new()
    {
        AllowRawPublicKeys = true,
    };
    DtlsServer server = new(options);

    try
    {
        using DtlsConnection connection = await server.AcceptAsync(transport, timeout.Token);
        Console.WriteLine("A DTLS connection was accepted.");
    }
    catch (NotImplementedException)
    {
        Console.WriteLine("Handshake not implemented yet; server usage is demonstrated.");
    }
    catch (OperationCanceledException)
    {
        Console.WriteLine("No datagram received during the brief sample run.");
    }

    return 0;
}
