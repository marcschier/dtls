// Copyright (c) marcschier. All rights reserved.
// Licensed under the MIT License. See LICENSE in the project root for license information.

using System;
using System.Net;
using System.Runtime.InteropServices;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using Dtls;
using Dtls.Transport;
using Xunit;

namespace Dtls.Interop.Tests;

/// <summary>
/// Interoperability tests against the OpenSSL reference implementation's command-line tool.
/// The DTLS 1.2 cases drive our OpenSSL-backed endpoints against <c>openssl s_server</c> and
/// <c>openssl s_client</c> over loopback UDP; they run only on Linux when the <c>openssl</c>
/// executable is present (CI installs it). DTLS 1.3 has no OpenSSL DTLS reference yet and is
/// validated by RFC 9147 vectors elsewhere.
/// </summary>
public sealed class OpenSslInteropTests
{
    private static readonly TimeSpan Timeout = TimeSpan.FromSeconds(20);

    [Fact]
    public void OpenSsl_Cli_IsAvailable_InCiOrInconclusiveLocally()
    {
        OpenSslResult result = OpenSslCli.TryGetVersion();
        if (!result.Available)
        {
            // OpenSSL is provided by CI runners but may be absent on a developer machine.
            return;
        }

        bool looksLikeOpenSsl =
            result.Version.Contains("SSL", StringComparison.OrdinalIgnoreCase);
        Assert.True(looksLikeOpenSsl, $"Unexpected 'openssl version' output: {result.Version}");
    }

    [Fact]
    public async Task OurClient_Interops_With_OpenSsl_SServer_Dtls12()
    {
        if (!InteropAvailable())
        {
            return;
        }

        using OpenSslTestCertificate certificate = OpenSslTestCertificate.CreateEcdsa();
        int port = OpenSslTestCertificate.FindFreeUdpPort();

        // 'openssl s_server' forwards whatever is written to its stdin to the connected peer as
        // application data. We keep its stdin open (so the interactive loop does not exit on
        // EOF) and, after the handshake, push a token through it to assert the server->client
        // protected data path. The handshake completing against the real OpenSSL stack is the
        // core interop proof for the client->server direction.
        using OpenSslProcess server = OpenSslProcess.Start(
            $"s_server -4 -dtls1_2 -accept {port} -cert \"{certificate.CertificatePath}\" "
            + $"-key \"{certificate.KeyPath}\"");

        await server.WaitForMarkerAsync("ACCEPT", TimeSpan.FromSeconds(10));

        using CancellationTokenSource cts = new(Timeout);
        using UdpDatagramTransport transport = UdpDatagramTransport.Connect(
            new IPEndPoint(IPAddress.Loopback, port));

        DtlsClientOptions options = new()
        {
            MinimumVersion = DtlsProtocolVersion.Dtls12,
            MaximumVersion = DtlsProtocolVersion.Dtls12,
            RemoteCertificateValidation = (_, _, _) => true,
            HandshakeTimeout = TimeSpan.FromSeconds(15),
        };

        using DtlsConnection connection = await DtlsClient.ConnectAsync(
            transport, options, cts.Token);
        Assert.Equal(DtlsProtocolVersion.Dtls12, connection.NegotiatedVersion);

        // Exercise the client->server protected data path.
        await connection.SendAsync(Encoding.ASCII.GetBytes("from-client\n"), cts.Token);

        // Push a token from the OpenSSL server back to our client and assert it round-trips.
        string token = "srv-" + Guid.NewGuid().ToString("N");
        await server.StandardInput.WriteLineAsync(token);
        await server.StandardInput.FlushAsync();

        string received = await ReadLineAsync(connection, cts.Token);
        Assert.Equal(token, received);
    }

    [Fact]
    public async Task OurServer_Interops_With_OpenSsl_SClient_Dtls12()
    {
        if (!InteropAvailable())
        {
            return;
        }

        using OpenSslTestCertificate certificate = OpenSslTestCertificate.CreateEcdsa();

        using CancellationTokenSource cts = new(Timeout);
        using LoopbackUdpServer listener = LoopbackUdpServer.Bind();

        using X509Certificate2 serverCertificate = LoadCertificateWithKey(certificate);
        DtlsServer server = new(new DtlsServerOptions
        {
            MinimumVersion = DtlsProtocolVersion.Dtls12,
            MaximumVersion = DtlsProtocolVersion.Dtls12,
            ServerCertificate = serverCertificate,
            HandshakeTimeout = TimeSpan.FromSeconds(15),
        });

        Task<DtlsConnection> acceptTask = listener.AcceptAsync(server, cts.Token);

        using OpenSslProcess client = OpenSslProcess.Start(
            $"s_client -4 -dtls1_2 -connect 127.0.0.1:{listener.Port}");

        string token = "interop-token-" + Guid.NewGuid().ToString("N");
        await client.StandardInput.WriteLineAsync(token);
        await client.StandardInput.FlushAsync();

        using DtlsConnection connection = await acceptTask;
        Assert.Equal(DtlsProtocolVersion.Dtls12, connection.NegotiatedVersion);

        byte[] buffer = new byte[1024];
        int read = await connection.ReceiveAsync(buffer, cts.Token);
        string received = Encoding.ASCII.GetString(buffer, 0, read).Trim('\r', '\n', '\0');
        Assert.Equal(token, received);
    }

    [Fact(Skip = "DTLS 1.3 has no OpenSSL reference yet; validated by RFC 9147 vectors instead.")]
    public void Dtls13_SelfInterop_ManagedClientAndServer()
    {
    }

    private static X509Certificate2 LoadCertificateWithKey(OpenSslTestCertificate certificate)
    {
        return X509Certificate2.CreateFromPemFile(
            certificate.CertificatePath, certificate.KeyPath);
    }

    private static async Task<string> ReadLineAsync(
        DtlsConnection connection, CancellationToken cancellationToken)
    {
        StringBuilder builder = new();
        byte[] buffer = new byte[1024];
        while (true)
        {
            int read = await connection.ReceiveAsync(buffer, cancellationToken);
            if (read <= 0)
            {
                break;
            }

            builder.Append(Encoding.ASCII.GetString(buffer, 0, read));
            int newline = builder.ToString().IndexOf('\n');
            if (newline >= 0)
            {
                return builder.ToString(0, newline).Trim('\r', '\0');
            }
        }

        return builder.ToString().Trim('\r', '\n', '\0');
    }

    private static bool InteropAvailable()
    {
        return RuntimeInformation.IsOSPlatform(OSPlatform.Linux)
            && OpenSslCli.TryGetVersion().Available;
    }
}
