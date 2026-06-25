// Copyright (c) marcschier. All rights reserved.
// Licensed under the MIT License. See LICENSE in the project root for license information.

using System;
using System.Collections.Generic;
using Dtls.Internal;

namespace Dtls.Protocol.V13.Handshake;

/// <summary>
/// The supported_groups extension (RFC 8446 section 4.2.7, type 10): a 16-bit
/// length-prefixed list of <see cref="NamedGroup"/> identifiers.
/// </summary>
internal static class SupportedGroupsExtension
{
    /// <summary>Encodes the extension_data from a list of named groups.</summary>
    public static byte[] Encode(IReadOnlyList<NamedGroup> groups)
    {
        if (groups is null)
        {
            throw new ArgumentNullException(nameof(groups));
        }

        TlsWriter writer = new(2 + (groups.Count * 2));
        int listStart = writer.BeginVector16();
        for (int i = 0; i < groups.Count; i++)
        {
            writer.WriteUInt16((ushort)groups[i]);
        }

        writer.EndVector16(listStart);
        return writer.ToArray();
    }

    /// <summary>Parses the extension_data into a list of named groups.</summary>
    public static bool TryParse(ReadOnlySpan<byte> data, out List<NamedGroup> groups)
    {
        groups = new List<NamedGroup>();

        SpanReader reader = new(data);
        if (!reader.TryReadVector16(out ReadOnlySpan<byte> listBytes) || reader.Remaining != 0)
        {
            return false;
        }

        if ((listBytes.Length % 2) != 0 || listBytes.IsEmpty)
        {
            return false;
        }

        SpanReader inner = new(listBytes);
        while (inner.TryReadUInt16(out ushort group))
        {
            groups.Add((NamedGroup)group);
        }

        return true;
    }
}
