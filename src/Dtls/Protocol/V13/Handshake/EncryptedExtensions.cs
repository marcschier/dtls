// Copyright (c) marcschier. All rights reserved.
// Licensed under the MIT License. See LICENSE in the project root for license information.

using System;
using System.Collections.Generic;
using Dtls.Internal;

namespace Dtls.Protocol.V13.Handshake;

/// <summary>
/// The EncryptedExtensions message body (RFC 8446 section 4.3.1): a single
/// <c>extensions&lt;0..2^16-1&gt;</c> list.
/// </summary>
internal static class EncryptedExtensions
{
    /// <summary>Encodes the EncryptedExtensions body.</summary>
    public static byte[] Encode(IReadOnlyList<HandshakeExtension> extensions)
    {
        if (extensions is null)
        {
            throw new ArgumentNullException(nameof(extensions));
        }

        TlsWriter writer = new(32);
        ExtensionList.Write(writer, extensions);
        return writer.ToArray();
    }

    /// <summary>Parses the EncryptedExtensions body.</summary>
    public static bool TryParse(
        ReadOnlySpan<byte> body,
        out List<HandshakeExtension> extensions)
    {
        return ExtensionList.TryParse(body, out extensions);
    }
}
