// Copyright (c) marcschier. All rights reserved.
// Licensed under the MIT License. See LICENSE in the project root for license information.

using System;
using System.Security.Cryptography;

namespace Dtls.Protocol.V12.Handshake;

/// <summary>
/// A stateless DTLS 1.2 HelloVerifyRequest cookie (RFC 6347 section 4.2.1). The server returns it
/// in a HelloVerifyRequest so the client proves return-routability of its source address before the
/// server commits handshake state, mitigating denial-of-service amplification. The cookie is an
/// HMAC over the client's ClientHello random under a per-process secret, so it is unforgeable and
/// requires no server-side state; because the client reuses the same random in its second
/// ClientHello (RFC 6347 section 4.2.1) the server can recompute and compare it.
/// </summary>
internal static class Dtls12Cookie
{
    /// <summary>The cookie length, in bytes (a truncated HMAC-SHA256).</summary>
    public const int CookieLength = 32;

    /// <summary>
    /// Builds the cookie for <paramref name="clientRandom"/> under <paramref name="secret"/>.
    /// </summary>
    public static byte[] Build(byte[] secret, ReadOnlySpan<byte> clientRandom)
    {
        if (secret is null)
        {
            throw new ArgumentNullException(nameof(secret));
        }

        using HMACSHA256 hmac = new(secret);
        return hmac.ComputeHash(clientRandom.ToArray());
    }

    /// <summary>
    /// Returns whether <paramref name="cookie"/> is the valid cookie for
    /// <paramref name="clientRandom"/> under <paramref name="secret"/>.
    /// </summary>
    public static bool Verify(
        byte[] secret,
        ReadOnlySpan<byte> clientRandom,
        ReadOnlySpan<byte> cookie)
    {
        if (cookie.Length != CookieLength)
        {
            return false;
        }

        byte[] expected = Build(secret, clientRandom);
        return CryptographicOperations.FixedTimeEquals(expected, cookie);
    }
}
