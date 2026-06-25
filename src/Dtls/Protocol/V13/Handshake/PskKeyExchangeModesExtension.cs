// Copyright (c) marcschier. All rights reserved.
// Licensed under the MIT License. See LICENSE in the project root for license information.

using System;
using System.Collections.Generic;
using Dtls.Internal;

namespace Dtls.Protocol.V13.Handshake;

/// <summary>
/// The psk_key_exchange_modes extension (RFC 8446 section 4.2.9, type 45): an 8-bit
/// length-prefixed list of <see cref="PskKeyExchangeMode"/> values.
/// </summary>
internal static class PskKeyExchangeModesExtension
{
    /// <summary>Encodes the extension_data from a list of modes.</summary>
    public static byte[] Encode(IReadOnlyList<PskKeyExchangeMode> modes)
    {
        if (modes is null)
        {
            throw new ArgumentNullException(nameof(modes));
        }

        TlsWriter writer = new(1 + modes.Count);
        int listStart = writer.BeginVector8();
        for (int i = 0; i < modes.Count; i++)
        {
            writer.WriteByte((byte)modes[i]);
        }

        writer.EndVector8(listStart);
        return writer.ToArray();
    }

    /// <summary>Parses the extension_data into a list of modes.</summary>
    public static bool TryParse(ReadOnlySpan<byte> data, out List<PskKeyExchangeMode> modes)
    {
        modes = new List<PskKeyExchangeMode>();

        SpanReader reader = new(data);
        if (!reader.TryReadVector8(out ReadOnlySpan<byte> listBytes) || reader.Remaining != 0)
        {
            return false;
        }

        if (listBytes.IsEmpty)
        {
            return false;
        }

        foreach (byte mode in listBytes)
        {
            modes.Add((PskKeyExchangeMode)mode);
        }

        return true;
    }
}
