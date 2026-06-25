// Copyright (c) marcschier. All rights reserved.
// Licensed under the MIT License. See LICENSE in the project root for license information.

using System;
using System.Collections.Generic;
using Dtls.Internal;

namespace Dtls.Protocol.V13.Handshake;

/// <summary>
/// The signature_algorithms extension (RFC 8446 section 4.2.3, type 13): a 16-bit
/// length-prefixed list of <see cref="SignatureScheme"/> (<c>uint16</c>) values that the
/// client supports for CertificateVerify and certificate-chain signatures.
/// </summary>
internal static class SignatureAlgorithmsExtension
{
    /// <summary>Encodes the extension_data from a list of signature schemes.</summary>
    public static byte[] Encode(IReadOnlyList<SignatureScheme> schemes)
    {
        if (schemes is null)
        {
            throw new ArgumentNullException(nameof(schemes));
        }

        TlsWriter writer = new(2 + (schemes.Count * 2));
        int listStart = writer.BeginVector16();
        for (int i = 0; i < schemes.Count; i++)
        {
            writer.WriteUInt16((ushort)schemes[i]);
        }

        writer.EndVector16(listStart);
        return writer.ToArray();
    }

    /// <summary>Parses the extension_data into a list of signature schemes.</summary>
    public static bool TryParse(ReadOnlySpan<byte> data, out List<SignatureScheme> schemes)
    {
        schemes = new List<SignatureScheme>();

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
        while (inner.TryReadUInt16(out ushort scheme))
        {
            schemes.Add((SignatureScheme)scheme);
        }

        return true;
    }
}
