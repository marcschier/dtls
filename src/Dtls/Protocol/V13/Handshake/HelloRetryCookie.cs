using System;
using System.Security.Cryptography;

namespace Dtls.Protocol.V13.Handshake;

/// <summary>
/// A stateless HelloRetryRequest cookie (RFC 9147 section 5.1 / RFC 8446 section 4.2.2). The
/// cookie lets the server force the client to prove return-routability of its address before
/// the server commits handshake state, mitigating denial-of-service amplification. It carries
/// the selected group and the transcript hash of the first ClientHello so the server can
/// reconstruct the post-HelloRetryRequest transcript from the returned cookie alone, and is
/// authenticated with an HMAC over a per-handshake secret so a client cannot forge or alter it.
/// </summary>
/// <remarks>
/// Wire layout (opaque to the client, which only echoes it):
/// <c>group(uint16) || hash_length(uint8) || client_hello1_hash || HMAC-SHA256(secret, prefix)</c>,
/// where <c>prefix</c> is every byte preceding the trailing 32-byte MAC.
/// </remarks>
internal static class HelloRetryCookie
{
    private const int MacLength = 32;
    private const int HeaderLength = 3;

    /// <summary>
    /// Builds an authenticated cookie binding <paramref name="group"/> and
    /// <paramref name="clientHello1Hash"/> under <paramref name="macKey"/>.
    /// </summary>
    public static byte[] Build(
        byte[] macKey,
        NamedGroup group,
        ReadOnlySpan<byte> clientHello1Hash)
    {
        if (macKey is null)
        {
            throw new ArgumentNullException(nameof(macKey));
        }

        if (clientHello1Hash.Length is < 1 or > 255)
        {
            throw new ArgumentException(
                "ClientHello hash length out of range.", nameof(clientHello1Hash));
        }

        int prefixLength = HeaderLength + clientHello1Hash.Length;
        byte[] cookie = new byte[prefixLength + MacLength];
        cookie[0] = (byte)((ushort)group >> 8);
        cookie[1] = (byte)(ushort)group;
        cookie[2] = (byte)clientHello1Hash.Length;
        clientHello1Hash.CopyTo(cookie.AsSpan(HeaderLength));

        using HMACSHA256 hmac = new(macKey);
        byte[] mac = hmac.ComputeHash(cookie, 0, prefixLength);
        mac.CopyTo(cookie, prefixLength);
        return cookie;
    }

    /// <summary>
    /// Verifies <paramref name="cookie"/> under <paramref name="macKey"/> and, on success,
    /// recovers the bound group and first-ClientHello transcript hash.
    /// </summary>
    public static bool TryOpen(
        byte[] macKey,
        ReadOnlySpan<byte> cookie,
        out NamedGroup group,
        out byte[] clientHello1Hash)
    {
        group = default;
        clientHello1Hash = Array.Empty<byte>();

        if (macKey is null || cookie.Length < HeaderLength + 1 + MacLength)
        {
            return false;
        }

        int hashLength = cookie[2];
        int prefixLength = HeaderLength + hashLength;
        if (cookie.Length != prefixLength + MacLength)
        {
            return false;
        }

        byte[] buffer = cookie.ToArray();
        byte[] expected;
        using (HMACSHA256 hmac = new(macKey))
        {
            expected = hmac.ComputeHash(buffer, 0, prefixLength);
        }

        if (!CryptographicOperations.FixedTimeEquals(
                expected, cookie.Slice(prefixLength, MacLength)))
        {
            return false;
        }

        group = (NamedGroup)((cookie[0] << 8) | cookie[1]);
        clientHello1Hash = cookie.Slice(HeaderLength, hashLength).ToArray();
        return true;
    }
}
