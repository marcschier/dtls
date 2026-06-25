// Copyright (c) marcschier. All rights reserved.
// Licensed under the MIT License. See LICENSE in the project root for license information.

using System;
using System.Security.Cryptography;
using Dtls.Protocol.V13.Handshake;
using Xunit;

namespace Dtls.UnitTests;

/// <summary>
/// Tests the stateless HelloRetryRequest cookie codec (RFC 9147 section 5.1 / RFC 8446
/// section 4.2.2): a round-trip recovers the bound group and ClientHello hash, and any
/// tampering (wrong key, altered bytes, truncation) is rejected by the HMAC.
/// </summary>
public sealed class HelloRetryCookieTests
{
    [Fact]
    public void Build_TryOpen_RoundTripsGroupAndHash()
    {
        byte[] key = RandomNumberGenerator.GetBytes(32);
        byte[] hash = RandomNumberGenerator.GetBytes(32);

        byte[] cookie = HelloRetryCookie.Build(key, NamedGroup.Secp384r1, hash);

        Assert.True(HelloRetryCookie.TryOpen(
            key, cookie, out NamedGroup group, out byte[] recoveredHash));
        Assert.Equal(NamedGroup.Secp384r1, group);
        Assert.Equal(hash, recoveredHash);
    }

    [Fact]
    public void TryOpen_WithWrongKey_Fails()
    {
        byte[] key = RandomNumberGenerator.GetBytes(32);
        byte[] otherKey = RandomNumberGenerator.GetBytes(32);
        byte[] hash = RandomNumberGenerator.GetBytes(48);

        byte[] cookie = HelloRetryCookie.Build(key, NamedGroup.Secp256r1, hash);

        Assert.False(HelloRetryCookie.TryOpen(otherKey, cookie, out _, out _));
    }

    [Fact]
    public void TryOpen_WithTamperedBytes_Fails()
    {
        byte[] key = RandomNumberGenerator.GetBytes(32);
        byte[] hash = RandomNumberGenerator.GetBytes(32);

        byte[] cookie = HelloRetryCookie.Build(key, NamedGroup.Secp256r1, hash);
        cookie[0] ^= 0xFF;

        Assert.False(HelloRetryCookie.TryOpen(key, cookie, out _, out _));
    }

    [Fact]
    public void TryOpen_WithTruncatedCookie_Fails()
    {
        byte[] key = RandomNumberGenerator.GetBytes(32);
        byte[] hash = RandomNumberGenerator.GetBytes(32);

        byte[] cookie = HelloRetryCookie.Build(key, NamedGroup.Secp256r1, hash);
        byte[] truncated = cookie.AsSpan(0, cookie.Length - 1).ToArray();

        Assert.False(HelloRetryCookie.TryOpen(key, truncated, out _, out _));
    }
}
