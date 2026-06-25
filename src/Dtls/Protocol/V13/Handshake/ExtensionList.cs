// Copyright (c) marcschier. All rights reserved.
// Licensed under the MIT License. See LICENSE in the project root for license information.

using System;
using System.Collections.Generic;
using Dtls.Internal;

namespace Dtls.Protocol.V13.Handshake;

/// <summary>
/// A single TLS 1.3 extension (RFC 8446 section 4.2):
/// <c>extension_type(uint16) || extension_data&lt;0..2^16-1&gt;</c>.
/// </summary>
internal readonly struct HandshakeExtension
{
    public HandshakeExtension(ExtensionType type, byte[] data)
    {
        Type = type;
        Data = data ?? throw new ArgumentNullException(nameof(data));
    }

    /// <summary>The registered extension type.</summary>
    public ExtensionType Type { get; }

    /// <summary>The opaque extension data.</summary>
    public byte[] Data { get; }
}

/// <summary>
/// Encoder/decoder for the TLS 1.3 extension list (RFC 8446 section 4.2): a 16-bit
/// length-prefixed sequence of <see cref="HandshakeExtension"/> structures.
/// </summary>
internal static class ExtensionList
{
    /// <summary>
    /// Writes a length-prefixed extension list (<c>extensions&lt;...&gt;</c>) into
    /// <paramref name="writer"/>.
    /// </summary>
    public static void Write(TlsWriter writer, IReadOnlyList<HandshakeExtension> extensions)
    {
        if (writer is null)
        {
            throw new ArgumentNullException(nameof(writer));
        }

        if (extensions is null)
        {
            throw new ArgumentNullException(nameof(extensions));
        }

        int listStart = writer.BeginVector16();
        for (int i = 0; i < extensions.Count; i++)
        {
            HandshakeExtension extension = extensions[i];
            writer.WriteUInt16((ushort)extension.Type);
            int dataStart = writer.BeginVector16();
            writer.WriteBytes(extension.Data);
            writer.EndVector16(dataStart);
        }

        writer.EndVector16(listStart);
    }

    /// <summary>
    /// Parses a length-prefixed extension list (<c>extensions&lt;...&gt;</c>) from
    /// <paramref name="source"/>. Duplicate extension types are rejected.
    /// </summary>
    public static bool TryParse(
        ReadOnlySpan<byte> source,
        out List<HandshakeExtension> extensions)
    {
        extensions = new List<HandshakeExtension>();

        SpanReader reader = new(source);
        if (!reader.TryReadUInt16(out ushort listLength))
        {
            return false;
        }

        if (!reader.TryReadBytes(listLength, out ReadOnlySpan<byte> listBytes))
        {
            return false;
        }

        if (reader.Remaining != 0)
        {
            return false;
        }

        HashSet<ushort> seen = new();
        SpanReader inner = new(listBytes);
        while (inner.Remaining > 0)
        {
            if (!inner.TryReadUInt16(out ushort type)
                || !inner.TryReadVector16(out ReadOnlySpan<byte> data))
            {
                extensions = new List<HandshakeExtension>();
                return false;
            }

            if (!seen.Add(type))
            {
                extensions = new List<HandshakeExtension>();
                return false;
            }

            extensions.Add(new HandshakeExtension((ExtensionType)type, data.ToArray()));
        }

        return true;
    }

    /// <summary>
    /// Returns the first extension of the requested <paramref name="type"/>, if present.
    /// </summary>
    public static bool TryFind(
        IReadOnlyList<HandshakeExtension> extensions,
        ExtensionType type,
        out HandshakeExtension extension)
    {
        if (extensions is null)
        {
            throw new ArgumentNullException(nameof(extensions));
        }

        for (int i = 0; i < extensions.Count; i++)
        {
            if (extensions[i].Type == type)
            {
                extension = extensions[i];
                return true;
            }
        }

        extension = default;
        return false;
    }
}
