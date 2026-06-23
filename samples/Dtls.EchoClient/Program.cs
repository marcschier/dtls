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
        (string host, int port, string message, bool selfTest) = ParseArgs(arguments);
        if (selfTest)
        {
            await RunSelfTestAsync();
            Console.WriteLine("selftest: OK");
            return 0;
        }

        return await RunClientAsync(host, port, message);
    }
    catch (Exception ex)
    {
        await Console.Error.WriteLineAsync("error: " + ex.Message);
        return 1;
    }
}

static (string Host, int Port, string Message, bool SelfTest) ParseArgs(string[] arguments)
{
    string host = "127.0.0.1";
    int port = 49555;
    string message = "hello";
    bool selfTest = false;

    for (int index = 0; index < arguments.Length; index++)
    {
        string argument = arguments[index];
        if (StringComparer.Ordinal.Equals(argument, "--selftest"))
        {
            selfTest = true;
            continue;
        }

        if (StringComparer.Ordinal.Equals(argument, "--host"))
        {
            host = ParseRequiredValue(arguments, ref index, "--host");
            continue;
        }

        if (StringComparer.Ordinal.Equals(argument, "--port"))
        {
            port = ParseRequiredPort(arguments, ref index);
            continue;
        }

        if (StringComparer.Ordinal.Equals(argument, "--message"))
        {
            message = ParseRequiredValue(arguments, ref index, "--message");
            continue;
        }

        throw new ArgumentException("Unknown argument: " + argument);
    }

    return (host, port, message, selfTest);
}

static string ParseRequiredValue(string[] arguments, ref int index, string optionName)
{
    if (index + 1 >= arguments.Length)
    {
        throw new ArgumentException(optionName + " requires a value.");
    }

    return arguments[++index];
}

static int ParseRequiredPort(string[] arguments, ref int index)
{
    string value = ParseRequiredValue(arguments, ref index, "--port");
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
        await VerifyDatagramAsync(endpointA, endpointB, "client to server");
        await VerifyDatagramAsync(endpointB, endpointA, "server to client");
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

static async Task<int> RunClientAsync(string host, int port, string message)
{
    IPEndPoint remoteEndPoint = await CreateRemoteEndPointAsync(host, port);

    Console.WriteLine(
        "DTLS echo client sample connecting to "
        + remoteEndPoint
        + ".");
    Console.WriteLine("The DTLS client handshake is under construction.");

    using UdpDatagramTransport transport = UdpDatagramTransport.Connect(remoteEndPoint);
    DtlsClientOptions options = new();

    try
    {
        using DtlsConnection connection = await DtlsClient.ConnectAsync(
            transport,
            options,
            CancellationToken.None);

        byte[] payload = Encoding.UTF8.GetBytes(message);
        await connection.SendAsync(payload, CancellationToken.None);
        Console.WriteLine("Message sent through the DTLS connection.");
    }
    catch (NotImplementedException)
    {
        Console.WriteLine("Handshake not implemented yet; client usage is demonstrated.");
    }

    return 0;
}

static async Task<IPEndPoint> CreateRemoteEndPointAsync(string host, int port)
{
    if (IPAddress.TryParse(host, out IPAddress? address))
    {
        return new IPEndPoint(address, port);
    }

    IPAddress[] addresses = await Dns.GetHostAddressesAsync(host);
    for (int index = 0; index < addresses.Length; index++)
    {
        IPAddress candidate = addresses[index];
        if (candidate.AddressFamily == AddressFamily.InterNetwork
            || candidate.AddressFamily == AddressFamily.InterNetworkV6)
        {
            return new IPEndPoint(candidate, port);
        }
    }

    throw new InvalidOperationException("No usable IP address found for host: " + host);
}
