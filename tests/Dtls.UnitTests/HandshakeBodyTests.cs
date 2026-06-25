// Copyright (c) marcschier. All rights reserved.
// Licensed under the MIT License. See LICENSE in the project root for license information.

using System;
using System.Collections.Generic;
using Dtls.Protocol.V13.Handshake;
using Xunit;

namespace Dtls.UnitTests;

/// <summary>
/// Encode/parse round-trips and bounds checks for the DTLS 1.3 handshake message bodies.
/// </summary>
public sealed class HandshakeBodyTests
{
    private static List<HandshakeExtension> SampleExtensions()
    {
        return new List<HandshakeExtension>
        {
            new HandshakeExtension(
                ExtensionType.SupportedVersions,
                SupportedVersionsExtension.EncodeClientHello(
                    new List<ushort> { DtlsWireVersion.Dtls13 })),
            new HandshakeExtension(
                ExtensionType.SupportedGroups,
                SupportedGroupsExtension.Encode(new List<NamedGroup> { NamedGroup.Secp256r1 })),
        };
    }

    [Fact]
    public void ClientHello_RoundTrips()
    {
        ClientHello hello = new()
        {
            Random = Fill(32, 0x10),
            LegacySessionId = Array.Empty<byte>(),
            Cookie = Array.Empty<byte>(),
            CipherSuites = new List<ushort> { 0x1301, 0x1303 },
            Extensions = SampleExtensions(),
        };

        byte[] body = hello.Encode();
        Assert.True(ClientHello.TryParse(body, out ClientHello parsed));
        Assert.Equal(hello.Random, parsed.Random);
        Assert.Equal(new ushort[] { 0x1301, 0x1303 }, parsed.CipherSuites);
        Assert.Equal(2, parsed.Extensions.Count);
        Assert.Equal(ExtensionType.SupportedVersions, parsed.Extensions[0].Type);
    }

    [Fact]
    public void ClientHello_WithCookie_RoundTrips()
    {
        ClientHello hello = new()
        {
            Random = Fill(32, 0x22),
            LegacySessionId = Fill(16, 0x01),
            Cookie = Fill(20, 0x05),
            CipherSuites = new List<ushort> { 0x1302 },
            Extensions = SampleExtensions(),
        };

        byte[] body = hello.Encode();
        Assert.True(ClientHello.TryParse(body, out ClientHello parsed));
        Assert.Equal(hello.Cookie, parsed.Cookie);
        Assert.Equal(hello.LegacySessionId, parsed.LegacySessionId);
    }

    [Fact]
    public void ClientHello_Truncated_Fails()
    {
        ClientHello hello = new()
        {
            Random = Fill(32, 0x10),
            CipherSuites = new List<ushort> { 0x1301 },
            Extensions = SampleExtensions(),
        };

        byte[] body = hello.Encode();
        for (int len = 0; len < body.Length; len++)
        {
            Assert.False(ClientHello.TryParse(body.AsSpan(0, len).ToArray(), out _));
        }
    }

    [Fact]
    public void ServerHello_RoundTrips()
    {
        ServerHello hello = new()
        {
            Random = Fill(32, 0x30),
            LegacySessionIdEcho = Fill(8, 0x07),
            CipherSuite = 0x1301,
            Extensions = new List<HandshakeExtension>
            {
                new HandshakeExtension(
                    ExtensionType.SupportedVersions,
                    SupportedVersionsExtension.EncodeServerHello(DtlsWireVersion.Dtls13)),
            },
        };

        byte[] body = hello.Encode();
        Assert.True(ServerHello.TryParse(body, out ServerHello parsed));
        Assert.Equal(hello.Random, parsed.Random);
        Assert.Equal(0x1301, parsed.CipherSuite);
        Assert.Equal(hello.LegacySessionIdEcho, parsed.LegacySessionIdEcho);
        Assert.False(parsed.IsHelloRetryRequest);
    }

    [Fact]
    public void ServerHello_HelloRetryRequest_IsDetected()
    {
        ServerHello hrr = new()
        {
            Random = ServerHello.HelloRetryRequestRandom.ToArray(),
            CipherSuite = 0x1301,
            Extensions = new List<HandshakeExtension>
            {
                new HandshakeExtension(
                    ExtensionType.KeyShare,
                    KeyShareExtension.EncodeHelloRetryRequest(NamedGroup.Secp256r1)),
            },
        };

        byte[] body = hrr.Encode();
        Assert.True(ServerHello.TryParse(body, out ServerHello parsed));
        Assert.True(parsed.IsHelloRetryRequest);
        Assert.True(ServerHello.IsHelloRetryRequestRandom(parsed.Random));
    }

    [Fact]
    public void ServerHello_Truncated_Fails()
    {
        ServerHello hello = new()
        {
            Random = Fill(32, 0x30),
            CipherSuite = 0x1301,
            Extensions = Array.Empty<HandshakeExtension>(),
        };

        byte[] body = hello.Encode();
        for (int len = 0; len < body.Length; len++)
        {
            Assert.False(ServerHello.TryParse(body.AsSpan(0, len).ToArray(), out _));
        }
    }

    [Fact]
    public void EncryptedExtensions_RoundTrips()
    {
        List<HandshakeExtension> extensions = new()
        {
            new HandshakeExtension(
                ExtensionType.SupportedGroups,
                SupportedGroupsExtension.Encode(new List<NamedGroup> { NamedGroup.Secp256r1 })),
        };

        byte[] body = EncryptedExtensions.Encode(extensions);
        Assert.True(EncryptedExtensions.TryParse(body, out List<HandshakeExtension> parsed));
        Assert.Single(parsed);
        Assert.Equal(ExtensionType.SupportedGroups, parsed[0].Type);
    }

    [Fact]
    public void EncryptedExtensions_Empty_RoundTrips()
    {
        byte[] body = EncryptedExtensions.Encode(Array.Empty<HandshakeExtension>());
        Assert.True(EncryptedExtensions.TryParse(body, out List<HandshakeExtension> parsed));
        Assert.Empty(parsed);
    }

    [Fact]
    public void Finished_RoundTrips()
    {
        byte[] verifyData = Fill(32, 0x55);
        byte[] body = FinishedMessage.Encode(verifyData);

        Assert.True(FinishedMessage.TryParse(body, 32, out byte[] parsed));
        Assert.Equal(verifyData, parsed);
    }

    [Fact]
    public void Finished_WrongLength_Fails()
    {
        byte[] body = Fill(32, 0x55);
        Assert.False(FinishedMessage.TryParse(body, 48, out _));
        Assert.False(FinishedMessage.TryParse(body, 0, out _));
    }

    private static byte[] Fill(int length, byte value)
    {
        byte[] buffer = new byte[length];
        Array.Fill(buffer, value);
        return buffer;
    }
}
