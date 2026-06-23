using Dtls.Routing;
using Xunit;

namespace Dtls.UnitTests;

/// <summary>
/// Tests the hybrid version router: a DTLS 1.3 ClientHello must route to the managed
/// engine, while 1.0/1.2 ClientHellos route to the native backend. Malformed or
/// fragmented input must never be misrouted.
/// </summary>
public sealed class ClientHelloVersionPeekTests
{
    [Fact]
    public void Dtls13ClientHello_RoutesToManaged()
    {
        byte[] datagram = DtlsMessageBuilder.BuildClientHello(offerDtls13: true);
        Assert.Equal(DtlsRoute.Managed13, ClientHelloVersionPeek.Inspect(datagram));
    }

    [Fact]
    public void Dtls12ClientHello_NoSupportedVersions_RoutesToNative()
    {
        byte[] datagram = DtlsMessageBuilder.BuildClientHello(offerDtls13: false);
        Assert.Equal(DtlsRoute.NativeLegacy, ClientHelloVersionPeek.Inspect(datagram));
    }

    [Fact]
    public void SupportedVersions_Without13_RoutesToNative()
    {
        // Offers only DTLS 1.2 (0xFEFD) in supported_versions.
        byte[] datagram = DtlsMessageBuilder.BuildClientHello(
            offerDtls13: false,
            extraVersions: new ushort[] { 0xFEFD });
        Assert.Equal(DtlsRoute.NativeLegacy, ClientHelloVersionPeek.Inspect(datagram));
    }

    [Fact]
    public void SupportedVersions_WithOtherVersionsAnd13_RoutesToManaged()
    {
        byte[] datagram = DtlsMessageBuilder.BuildClientHello(
            offerDtls13: true,
            extraVersions: new ushort[] { 0xFEFD, 0x0304 });
        Assert.Equal(DtlsRoute.Managed13, ClientHelloVersionPeek.Inspect(datagram));
    }

    [Fact]
    public void NonHandshakeRecord_IsUnknown()
    {
        byte[] datagram = DtlsMessageBuilder.BuildClientHello(
            offerDtls13: true,
            contentType: 23); // application_data
        Assert.Equal(DtlsRoute.Unknown, ClientHelloVersionPeek.Inspect(datagram));
    }

    [Fact]
    public void FragmentedClientHello_NonZeroOffset_IsUnknown()
    {
        byte[] datagram = DtlsMessageBuilder.BuildClientHello(
            offerDtls13: true,
            fragmentOffset: 16);
        Assert.Equal(DtlsRoute.Unknown, ClientHelloVersionPeek.Inspect(datagram));
    }

    [Fact]
    public void TruncatedDatagram_IsUnknown()
    {
        byte[] datagram = DtlsMessageBuilder.BuildClientHello(offerDtls13: true);
        byte[] truncated = datagram[..10];
        Assert.Equal(DtlsRoute.Unknown, ClientHelloVersionPeek.Inspect(truncated));
    }

    [Fact]
    public void Empty_IsUnknown()
    {
        Assert.Equal(DtlsRoute.Unknown, ClientHelloVersionPeek.Inspect(default));
    }
}
