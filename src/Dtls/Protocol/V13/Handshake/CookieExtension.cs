using System;
using Dtls.Internal;

namespace Dtls.Protocol.V13.Handshake;

/// <summary>
/// The cookie extension (RFC 8446 section 4.2.2, type 44): a single
/// <c>opaque cookie&lt;1..2^16-1&gt;</c>.
/// </summary>
internal static class CookieExtension
{
    /// <summary>Encodes the extension_data wrapping <paramref name="cookie"/>.</summary>
    public static byte[] Encode(ReadOnlySpan<byte> cookie)
    {
        if (cookie.IsEmpty || cookie.Length > ushort.MaxValue)
        {
            throw new ArgumentException("Cookie length out of range.", nameof(cookie));
        }

        TlsWriter writer = new(2 + cookie.Length);
        int start = writer.BeginVector16();
        writer.WriteBytes(cookie);
        writer.EndVector16(start);
        return writer.ToArray();
    }

    /// <summary>Parses the extension_data into the cookie bytes.</summary>
    public static bool TryParse(ReadOnlySpan<byte> data, out byte[] cookie)
    {
        cookie = Array.Empty<byte>();

        SpanReader reader = new(data);
        if (!reader.TryReadVector16(out ReadOnlySpan<byte> value) || reader.Remaining != 0)
        {
            return false;
        }

        if (value.IsEmpty)
        {
            return false;
        }

        cookie = value.ToArray();
        return true;
    }
}
