// Copyright (c) marcschier. All rights reserved.
// Licensed under the MIT License. See LICENSE in the project root for license information.

using System;
using System.Collections.Generic;
using Dtls.Internal;

namespace Dtls.Protocol.V13.Handshake;

/// <summary>
/// The supported_versions extension (RFC 8446 section 4.2.1, type 43). The ClientHello
/// form carries an 8-bit length-prefixed list of <c>uint16</c> versions; the ServerHello
/// form carries a single selected <c>uint16</c> version.
/// </summary>
internal static class SupportedVersionsExtension
{
    /// <summary>Encodes the ClientHello extension_data: a list of offered versions.</summary>
    public static byte[] EncodeClientHello(IReadOnlyList<ushort> versions)
    {
        if (versions is null)
        {
            throw new ArgumentNullException(nameof(versions));
        }

        TlsWriter writer = new(1 + (versions.Count * 2));
        int listStart = writer.BeginVector8();
        for (int i = 0; i < versions.Count; i++)
        {
            writer.WriteUInt16(versions[i]);
        }

        writer.EndVector8(listStart);
        return writer.ToArray();
    }

    /// <summary>Parses the ClientHello extension_data into the offered version list.</summary>
    public static bool TryParseClientHello(ReadOnlySpan<byte> data, out List<ushort> versions)
    {
        versions = new List<ushort>();

        SpanReader reader = new(data);
        if (!reader.TryReadVector8(out ReadOnlySpan<byte> listBytes) || reader.Remaining != 0)
        {
            return false;
        }

        if ((listBytes.Length % 2) != 0 || listBytes.IsEmpty)
        {
            return false;
        }

        SpanReader inner = new(listBytes);
        while (inner.TryReadUInt16(out ushort version))
        {
            versions.Add(version);
        }

        return true;
    }

    /// <summary>Encodes the ServerHello extension_data: a single selected version.</summary>
    public static byte[] EncodeServerHello(ushort selectedVersion)
    {
        byte[] data = new byte[2];
        data[0] = (byte)(selectedVersion >> 8);
        data[1] = (byte)selectedVersion;
        return data;
    }

    /// <summary>Parses the ServerHello extension_data into the selected version.</summary>
    public static bool TryParseServerHello(ReadOnlySpan<byte> data, out ushort selectedVersion)
    {
        selectedVersion = 0;

        SpanReader reader = new(data);
        if (!reader.TryReadUInt16(out selectedVersion) || reader.Remaining != 0)
        {
            return false;
        }

        return true;
    }
}
