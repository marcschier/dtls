using System;

namespace Dtls.Protocol.V13.Handshake;

/// <summary>
/// Encoder/decoder for the DTLS 1.3 <c>connection_id</c> extension data (RFC 9146 section 4):
/// <c>opaque cid&lt;0..2^8-1&gt;</c>. Each endpoint sends the Connection ID it wants the peer to
/// place on records sent to it; the peer then includes that CID on every protected record.
/// </summary>
internal static class ConnectionIdExtension
{
    /// <summary>The maximum Connection ID length carried by the 8-bit length prefix.</summary>
    public const int MaxLength = byte.MaxValue;

    /// <summary>
    /// Encodes a <c>connection_id</c> extension body for <paramref name="connectionId"/>.
    /// </summary>
    public static byte[] Encode(ReadOnlySpan<byte> connectionId)
    {
        if (connectionId.Length > MaxLength)
        {
            throw new ArgumentException(
                "Connection ID exceeds the 8-bit length prefix.", nameof(connectionId));
        }

        byte[] data = new byte[1 + connectionId.Length];
        data[0] = (byte)connectionId.Length;
        connectionId.CopyTo(data.AsSpan(1));
        return data;
    }

    /// <summary>Parses a <c>connection_id</c> extension body into its CID bytes.</summary>
    public static bool TryParse(ReadOnlySpan<byte> data, out byte[] connectionId)
    {
        connectionId = Array.Empty<byte>();
        if (data.Length < 1)
        {
            return false;
        }

        int length = data[0];
        if (1 + length != data.Length)
        {
            return false;
        }

        connectionId = data.Slice(1, length).ToArray();
        return true;
    }
}
