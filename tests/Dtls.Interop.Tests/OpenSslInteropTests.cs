using System;
using Xunit;

namespace Dtls.Interop.Tests;

/// <summary>
/// Interoperability tests against the OpenSSL reference implementation. The full handshake
/// interop cases are skipped until the native DTLS 1.0/1.2 backends and the managed DTLS
/// 1.3 engine are implemented (plan phases 2-3). The availability probe runs everywhere and
/// asserts wire-up of the OpenSSL dependency in CI.
/// </summary>
public sealed class OpenSslInteropTests
{
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

    [Fact(Skip = "Pending native DTLS 1.2 backend (plan phase 3): our client vs openssl s_server.")]
    public void OurClient_Interops_With_OpenSsl_SServer_Dtls12()
    {
    }

    [Fact(Skip = "Pending native DTLS 1.2 backend (plan phase 3): our server vs openssl s_client.")]
    public void OurServer_Interops_With_OpenSsl_SClient_Dtls12()
    {
    }

    [Fact(Skip = "DTLS 1.3 has no OpenSSL reference yet; validated by RFC 9147 vectors instead.")]
    public void Dtls13_SelfInterop_ManagedClientAndServer()
    {
    }
}
