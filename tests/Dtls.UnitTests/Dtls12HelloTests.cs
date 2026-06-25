// Copyright (c) marcschier. All rights reserved.
// Licensed under the MIT License. See LICENSE in the project root for license information.

using System;
using System.Collections.Generic;
using Dtls.Protocol.V12.Handshake;
using Dtls.Protocol.V13.Handshake;
using Xunit;

namespace Dtls.UnitTests;

/// <summary>
/// Round-trip tests for the DTLS 1.2 hello message codecs (RFC 6347 / RFC 5246): ClientHello with
/// the DTLS cookie field, HelloVerifyRequest, and ServerHello.
/// </summary>
public sealed class Dtls12HelloTests
{
    [Fact]
    public void ClientHello_RoundTrips()
    {
        Dtls12ClientHello hello = new()
        {
            Random = NewBytes(32, 1),
            SessionId = Array.Empty<byte>(),
            Cookie = NewBytes(20, 9),
            CipherSuites = new ushort[] { 0xC02B, 0xC02F, 0xD001 },
            Extensions = new List<HandshakeExtension>
            {
                new(ExtensionType.SupportedGroups, new byte[] { 0x00, 0x02, 0x00, 0x17 }),
            },
        };

        byte[] encoded = hello.Encode();
        Assert.True(Dtls12ClientHello.TryParse(encoded, out Dtls12ClientHello parsed));

        Assert.Equal(hello.Random, parsed.Random);
        Assert.Equal(hello.Cookie, parsed.Cookie);
        Assert.Equal(hello.CipherSuites, parsed.CipherSuites);
        Assert.Single(parsed.Extensions);
        Assert.Equal(ExtensionType.SupportedGroups, parsed.Extensions[0].Type);
    }

    [Fact]
    public void ClientHello_NoExtensions_RoundTrips()
    {
        Dtls12ClientHello hello = new()
        {
            Random = NewBytes(32, 2),
            Cookie = Array.Empty<byte>(),
            CipherSuites = new ushort[] { 0xC02B },
        };

        byte[] encoded = hello.Encode();
        Assert.True(Dtls12ClientHello.TryParse(encoded, out Dtls12ClientHello parsed));
        Assert.Equal(hello.CipherSuites, parsed.CipherSuites);
        Assert.Empty(parsed.Cookie);
    }

    [Fact]
    public void HelloVerifyRequest_RoundTrips()
    {
        byte[] cookie = NewBytes(16, 7);
        byte[] encoded = Dtls12HelloVerifyRequest.Encode(cookie);

        Assert.True(Dtls12HelloVerifyRequest.TryParse(encoded, out byte[] parsed));
        Assert.Equal(cookie, parsed);
    }

    [Fact]
    public void ServerHello_RoundTrips()
    {
        Dtls12ServerHello hello = new()
        {
            Random = NewBytes(32, 3),
            SessionId = NewBytes(8, 4),
            CipherSuite = 0xC02F,
            Extensions = new List<HandshakeExtension>
            {
                new(ExtensionType.SupportedGroups, Array.Empty<byte>()),
            },
        };

        byte[] encoded = hello.Encode();
        Assert.True(Dtls12ServerHello.TryParse(encoded, out Dtls12ServerHello parsed));

        Assert.Equal(hello.Random, parsed.Random);
        Assert.Equal(hello.SessionId, parsed.SessionId);
        Assert.Equal(hello.CipherSuite, parsed.CipherSuite);
        Assert.Single(parsed.Extensions);
    }

    private static byte[] NewBytes(int length, byte seed)
    {
        byte[] bytes = new byte[length];
        for (int i = 0; i < length; i++)
        {
            bytes[i] = (byte)(seed + i);
        }

        return bytes;
    }
}
