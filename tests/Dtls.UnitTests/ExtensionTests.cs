// Copyright (c) marcschier. All rights reserved.
// Licensed under the MIT License. See LICENSE in the project root for license information.

using System;
using System.Collections.Generic;
using Dtls.Internal;
using Dtls.Protocol.V13.Handshake;
using Xunit;

namespace Dtls.UnitTests;

/// <summary>
/// Encode/parse round-trips and bounds checking for the TLS 1.3 / DTLS 1.3 extensions
/// used in a psk_dhe_ke handshake (RFC 8446 section 4.2).
/// </summary>
public sealed class ExtensionTests
{
    [Fact]
    public void ExtensionList_RoundTrips()
    {
        List<HandshakeExtension> extensions = new()
        {
            new HandshakeExtension(ExtensionType.SupportedVersions, new byte[] { 1, 2 }),
            new HandshakeExtension(ExtensionType.Cookie, new byte[] { 9 }),
        };

        TlsWriter writer = new();
        ExtensionList.Write(writer, extensions);

        Assert.True(ExtensionList.TryParse(
            writer.WrittenSpan,
            out List<HandshakeExtension> parsed));
        Assert.Equal(2, parsed.Count);
        Assert.Equal(ExtensionType.SupportedVersions, parsed[0].Type);
        Assert.Equal(new byte[] { 1, 2 }, parsed[0].Data);
        Assert.Equal(ExtensionType.Cookie, parsed[1].Type);
    }

    [Fact]
    public void ExtensionList_DuplicateType_Fails()
    {
        List<HandshakeExtension> extensions = new()
        {
            new HandshakeExtension(ExtensionType.Cookie, new byte[] { 1 }),
            new HandshakeExtension(ExtensionType.Cookie, new byte[] { 2 }),
        };

        TlsWriter writer = new();
        ExtensionList.Write(writer, extensions);
        Assert.False(ExtensionList.TryParse(writer.WrittenSpan, out _));
    }

    [Fact]
    public void ExtensionList_Truncated_Fails()
    {
        Assert.False(ExtensionList.TryParse(new byte[] { 0x00 }, out _));
        Assert.False(ExtensionList.TryParse(new byte[] { 0x00, 0x04, 0x00, 0x2B }, out _));
    }

    [Fact]
    public void SupportedVersions_ClientHello_RoundTrips()
    {
        List<ushort> versions = new() { DtlsWireVersion.Dtls13, DtlsWireVersion.Dtls12 };
        byte[] data = SupportedVersionsExtension.EncodeClientHello(versions);

        Assert.True(SupportedVersionsExtension.TryParseClientHello(data, out List<ushort> parsed));
        Assert.Equal(versions, parsed);
    }

    [Fact]
    public void SupportedVersions_ServerHello_RoundTrips()
    {
        byte[] data = SupportedVersionsExtension.EncodeServerHello(DtlsWireVersion.Dtls13);
        Assert.True(SupportedVersionsExtension.TryParseServerHello(data, out ushort version));
        Assert.Equal(DtlsWireVersion.Dtls13, version);
    }

    [Fact]
    public void SupportedVersions_ClientHello_OddLength_Fails()
    {
        Assert.False(SupportedVersionsExtension.TryParseClientHello(
            new byte[] { 0x03, 0xFE, 0xFC, 0x00 },
            out _));
    }

    [Fact]
    public void SupportedVersions_ServerHello_Oversized_Fails()
    {
        Assert.False(SupportedVersionsExtension.TryParseServerHello(
            new byte[] { 0xFE, 0xFC, 0x00 },
            out _));
    }

    [Fact]
    public void SupportedGroups_RoundTrips()
    {
        List<NamedGroup> groups = new()
        {
            NamedGroup.Secp256r1,
            NamedGroup.Secp384r1,
            NamedGroup.X25519,
        };
        byte[] data = SupportedGroupsExtension.Encode(groups);

        Assert.True(SupportedGroupsExtension.TryParse(data, out List<NamedGroup> parsed));
        Assert.Equal(groups, parsed);
    }

    [Fact]
    public void SupportedGroups_Truncated_Fails()
    {
        Assert.False(SupportedGroupsExtension.TryParse(new byte[] { 0x00, 0x02, 0x00 }, out _));
    }

    [Fact]
    public void PskKeyExchangeModes_RoundTrips()
    {
        List<PskKeyExchangeMode> modes = new()
        {
            PskKeyExchangeMode.PskDheKe,
            PskKeyExchangeMode.PskKe,
        };
        byte[] data = PskKeyExchangeModesExtension.Encode(modes);

        Assert.True(PskKeyExchangeModesExtension.TryParse(
            data,
            out List<PskKeyExchangeMode> parsed));
        Assert.Equal(modes, parsed);
    }

    [Fact]
    public void PskKeyExchangeModes_Empty_Fails()
    {
        Assert.False(PskKeyExchangeModesExtension.TryParse(new byte[] { 0x00 }, out _));
    }

    [Fact]
    public void Cookie_RoundTrips()
    {
        byte[] cookie = { 0xDE, 0xAD, 0xBE, 0xEF };
        byte[] data = CookieExtension.Encode(cookie);

        Assert.True(CookieExtension.TryParse(data, out byte[] parsed));
        Assert.Equal(cookie, parsed);
    }

    [Fact]
    public void Cookie_Empty_Fails()
    {
        Assert.False(CookieExtension.TryParse(new byte[] { 0x00, 0x00 }, out _));
    }

    [Fact]
    public void KeyShare_ClientHello_RoundTrips()
    {
        List<KeyShareEntry> entries = new()
        {
            new KeyShareEntry(NamedGroup.Secp256r1, MakePoint(65)),
            new KeyShareEntry(NamedGroup.X25519, MakePoint(32)),
        };
        byte[] data = KeyShareExtension.EncodeClientHello(entries);

        Assert.True(KeyShareExtension.TryParseClientHello(data, out List<KeyShareEntry> parsed));
        Assert.Equal(2, parsed.Count);
        Assert.Equal(NamedGroup.Secp256r1, parsed[0].Group);
        Assert.Equal(entries[0].KeyExchange, parsed[0].KeyExchange);
        Assert.Equal(entries[1].KeyExchange, parsed[1].KeyExchange);
    }

    [Fact]
    public void KeyShare_ServerHello_RoundTrips()
    {
        KeyShareEntry entry = new(NamedGroup.Secp384r1, MakePoint(97));
        byte[] data = KeyShareExtension.EncodeServerHello(entry);

        Assert.True(KeyShareExtension.TryParseServerHello(data, out KeyShareEntry parsed));
        Assert.Equal(NamedGroup.Secp384r1, parsed.Group);
        Assert.Equal(entry.KeyExchange, parsed.KeyExchange);
    }

    [Fact]
    public void KeyShare_HelloRetryRequest_RoundTrips()
    {
        byte[] data = KeyShareExtension.EncodeHelloRetryRequest(NamedGroup.Secp521r1);
        Assert.True(KeyShareExtension.TryParseHelloRetryRequest(data, out NamedGroup group));
        Assert.Equal(NamedGroup.Secp521r1, group);
    }

    [Fact]
    public void KeyShare_ServerHello_Truncated_Fails()
    {
        Assert.False(KeyShareExtension.TryParseServerHello(
            new byte[] { 0x00, 0x17, 0x00, 0x05, 0x04 },
            out _));
    }

    [Fact]
    public void ServerCertificateType_ClientHello_RoundTrips()
    {
        List<CertificateType> types = new()
        {
            CertificateType.RawPublicKey,
            CertificateType.X509,
        };
        byte[] data = ServerCertificateTypeExtension.EncodeClientHello(types);

        Assert.True(ServerCertificateTypeExtension.TryParseClientHello(
            data, out List<CertificateType> parsed));
        Assert.Equal(types, parsed);
    }

    [Fact]
    public void ServerCertificateType_ServerHello_RoundTrips()
    {
        byte[] data = ServerCertificateTypeExtension.EncodeServerHello(
            CertificateType.RawPublicKey);

        Assert.True(ServerCertificateTypeExtension.TryParseServerHello(
            data, out CertificateType parsed));
        Assert.Equal(CertificateType.RawPublicKey, parsed);
    }

    [Fact]
    public void ServerCertificateType_ClientHello_Empty_Fails()
    {
        Assert.False(ServerCertificateTypeExtension.TryParseClientHello(
            new byte[] { 0x00 }, out _));
    }

    [Fact]
    public void ServerCertificateType_ServerHello_Oversized_Fails()
    {
        Assert.False(ServerCertificateTypeExtension.TryParseServerHello(
            new byte[] { 0x02, 0x00 }, out _));
    }

    private static byte[] MakePoint(int length)
    {
        byte[] point = new byte[length];
        for (int i = 0; i < length; i++)
        {
            point[i] = (byte)(i + 1);
        }

        return point;
    }
}
