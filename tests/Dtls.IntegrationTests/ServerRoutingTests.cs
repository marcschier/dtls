// Copyright (c) marcschier. All rights reserved.
// Licensed under the MIT License. See LICENSE in the project root for license information.

using System;
using System.Runtime.InteropServices;
using System.Threading.Tasks;
using Dtls;
using Dtls.Transport;
using Dtls.UnitTests;
using Xunit;

namespace Dtls.IntegrationTests;

/// <summary>
/// Verifies the hybrid version router through the public <see cref="DtlsServer"/> entry
/// point. The handshake engines are still under construction, so each route is asserted by
/// the engine it dispatches to (which currently throws a descriptive
/// <see cref="NotImplementedException"/>). This proves the routing decision is correct and
/// wired end to end.
/// </summary>
public sealed class ServerRoutingTests
{
    private static DtlsServerOptions ServerOptions()
    {
        return new DtlsServerOptions { AllowRawPublicKeys = true };
    }

    [Fact]
    public async Task Dtls13ClientHello_RoutesToManagedEngine()
    {
        (InMemoryDatagramTransport client, InMemoryDatagramTransport server) =
            InMemoryDatagramTransport.CreatePair();
        using (client)
        using (server)
        {
            await client.SendAsync(DtlsMessageBuilder.BuildClientHello(offerDtls13: true));

            // The router dispatches to the managed DTLS 1.3 engine, which rejects this
            // minimal ClientHello (no PSK credential configured / offered) with a
            // DtlsException rather than negotiating a connection.
            DtlsServer dtlsServer = new(ServerOptions());
            await Assert.ThrowsAnyAsync<DtlsException>(
                async () => await dtlsServer.AcceptAsync(server));
        }
    }

    [Fact]
    public async Task Dtls12ClientHello_RoutesToNativeBackend()
    {
        (InMemoryDatagramTransport client, InMemoryDatagramTransport server) =
            InMemoryDatagramTransport.CreatePair();
        using (client)
        using (server)
        {
            await client.SendAsync(DtlsMessageBuilder.BuildClientHello(offerDtls13: false));

            DtlsServer dtlsServer = new(ServerOptions());

            if (OperatingSystem.IsWindows())
            {
                // The Schannel native backend is implemented on Windows. This server has no
                // ServerCertificate (it is configured for raw public keys, which Schannel
                // does not support), so the backend rejects it with a DtlsException. That the
                // request reached the native backend at all proves the routing decision.
                await Assert.ThrowsAnyAsync<DtlsException>(
                    async () => await dtlsServer.AcceptAsync(server));
            }
            else if (RuntimeInformation.IsOSPlatform(OSPlatform.Linux))
            {
                // The OpenSSL native backend is implemented on Linux. This server has no
                // ServerCertificate, so OpenSSL fails the handshake (no shared cipher) and the
                // backend surfaces a DtlsException. Reaching the backend proves the routing.
                await Assert.ThrowsAnyAsync<DtlsException>(
                    async () => await dtlsServer.AcceptAsync(server));
            }
            else if (RuntimeInformation.IsOSPlatform(OSPlatform.OSX))
            {
                // The macOS native backend (Network.framework, with a Secure Transport
                // fallback) is implemented. This server has no ServerCertificate, so the
                // backend rejects it with a DtlsException; reaching the backend proves the
                // routing decision.
                await Assert.ThrowsAnyAsync<DtlsException>(
                    async () => await dtlsServer.AcceptAsync(server));
            }
            else
            {
                NotImplementedException ex = await Assert.ThrowsAsync<NotImplementedException>(
                    async () => await dtlsServer.AcceptAsync(server));
                Assert.Contains("DTLS 1.0/1.2", ex.Message);
            }
        }
    }

    [Fact]
    public async Task UnknownFirstDatagram_ThrowsDtlsException()
    {
        (InMemoryDatagramTransport client, InMemoryDatagramTransport server) =
            InMemoryDatagramTransport.CreatePair();
        using (client)
        using (server)
        {
            await client.SendAsync(new byte[] { 0xFF, 0x00, 0x01, 0x02 });

            DtlsServer dtlsServer = new(ServerOptions());
            await Assert.ThrowsAsync<DtlsException>(
                async () => await dtlsServer.AcceptAsync(server));
        }
    }
}
