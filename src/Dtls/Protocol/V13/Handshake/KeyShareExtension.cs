using System;
using System.Collections.Generic;
using Dtls.Internal;

namespace Dtls.Protocol.V13.Handshake;

/// <summary>
/// A single key_share entry (RFC 8446 section 4.2.8):
/// <c>group(uint16) || key_exchange&lt;1..2^16-1&gt;</c>.
/// </summary>
internal readonly struct KeyShareEntry
{
    public KeyShareEntry(NamedGroup group, byte[] keyExchange)
    {
        if (keyExchange is null)
        {
            throw new ArgumentNullException(nameof(keyExchange));
        }

        if (keyExchange.Length is < 1 or > ushort.MaxValue)
        {
            throw new ArgumentException("key_exchange length out of range.", nameof(keyExchange));
        }

        Group = group;
        KeyExchange = keyExchange;
    }

    /// <summary>The named group of this share.</summary>
    public NamedGroup Group { get; }

    /// <summary>The opaque key exchange (e.g. an uncompressed EC point).</summary>
    public byte[] KeyExchange { get; }
}

/// <summary>
/// Encoder/decoder for the key_share extension (RFC 8446 section 4.2.8, type 51) in its
/// three forms: ClientHello (a list of entries), ServerHello (a single entry), and
/// HelloRetryRequest (only a selected group).
/// </summary>
internal static class KeyShareExtension
{
    /// <summary>Encodes the ClientHello extension_data: a list of key_share entries.</summary>
    public static byte[] EncodeClientHello(IReadOnlyList<KeyShareEntry> entries)
    {
        if (entries is null)
        {
            throw new ArgumentNullException(nameof(entries));
        }

        TlsWriter writer = new(64);
        int listStart = writer.BeginVector16();
        for (int i = 0; i < entries.Count; i++)
        {
            WriteEntry(writer, entries[i]);
        }

        writer.EndVector16(listStart);
        return writer.ToArray();
    }

    /// <summary>Parses the ClientHello extension_data into a list of key_share entries.</summary>
    public static bool TryParseClientHello(
        ReadOnlySpan<byte> data,
        out List<KeyShareEntry> entries)
    {
        entries = new List<KeyShareEntry>();

        SpanReader reader = new(data);
        if (!reader.TryReadVector16(out ReadOnlySpan<byte> listBytes) || reader.Remaining != 0)
        {
            return false;
        }

        SpanReader inner = new(listBytes);
        while (inner.Remaining > 0)
        {
            if (!TryReadEntry(ref inner, out KeyShareEntry entry))
            {
                entries = new List<KeyShareEntry>();
                return false;
            }

            entries.Add(entry);
        }

        return true;
    }

    /// <summary>Encodes the ServerHello extension_data: a single key_share entry.</summary>
    public static byte[] EncodeServerHello(KeyShareEntry entry)
    {
        TlsWriter writer = new(8 + entry.KeyExchange.Length);
        WriteEntry(writer, entry);
        return writer.ToArray();
    }

    /// <summary>Parses the ServerHello extension_data into a single key_share entry.</summary>
    public static bool TryParseServerHello(ReadOnlySpan<byte> data, out KeyShareEntry entry)
    {
        entry = default;

        SpanReader reader = new(data);
        if (!TryReadEntry(ref reader, out entry) || reader.Remaining != 0)
        {
            return false;
        }

        return true;
    }

    /// <summary>Encodes the HelloRetryRequest extension_data: only a selected group.</summary>
    public static byte[] EncodeHelloRetryRequest(NamedGroup selectedGroup)
    {
        byte[] data = new byte[2];
        data[0] = (byte)((ushort)selectedGroup >> 8);
        data[1] = (byte)(ushort)selectedGroup;
        return data;
    }

    /// <summary>Parses the HelloRetryRequest extension_data into the selected group.</summary>
    public static bool TryParseHelloRetryRequest(
        ReadOnlySpan<byte> data,
        out NamedGroup selectedGroup)
    {
        selectedGroup = default;

        SpanReader reader = new(data);
        if (!reader.TryReadUInt16(out ushort group) || reader.Remaining != 0)
        {
            return false;
        }

        selectedGroup = (NamedGroup)group;
        return true;
    }

    private static void WriteEntry(TlsWriter writer, KeyShareEntry entry)
    {
        writer.WriteUInt16((ushort)entry.Group);
        int keyStart = writer.BeginVector16();
        writer.WriteBytes(entry.KeyExchange);
        writer.EndVector16(keyStart);
    }

    private static bool TryReadEntry(ref SpanReader reader, out KeyShareEntry entry)
    {
        entry = default;

        if (!reader.TryReadUInt16(out ushort group)
            || !reader.TryReadVector16(out ReadOnlySpan<byte> keyExchange))
        {
            return false;
        }

        if (keyExchange.IsEmpty)
        {
            return false;
        }

        entry = new KeyShareEntry((NamedGroup)group, keyExchange.ToArray());
        return true;
    }
}
