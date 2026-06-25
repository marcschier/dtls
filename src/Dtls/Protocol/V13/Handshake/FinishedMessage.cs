// Copyright (c) marcschier. All rights reserved.
// Licensed under the MIT License. See LICENSE in the project root for license information.

using System;

namespace Dtls.Protocol.V13.Handshake;

/// <summary>
/// The Finished message body (RFC 8446 section 4.4.4): the <c>verify_data</c> HMAC, whose
/// length equals the negotiated hash output length. The body is just the raw verify_data
/// bytes (no length prefix), so the parser is bounded by the handshake message length.
/// </summary>
internal static class FinishedMessage
{
    /// <summary>Encodes the Finished body, which equals <paramref name="verifyData"/>.</summary>
    public static byte[] Encode(ReadOnlySpan<byte> verifyData)
    {
        if (verifyData.IsEmpty)
        {
            throw new ArgumentException("verify_data must not be empty.", nameof(verifyData));
        }

        return verifyData.ToArray();
    }

    /// <summary>
    /// Parses the Finished body. The body must be exactly <paramref name="hashLength"/>
    /// bytes long (the negotiated hash output length).
    /// </summary>
    public static bool TryParse(
        ReadOnlySpan<byte> body,
        int hashLength,
        out byte[] verifyData)
    {
        verifyData = Array.Empty<byte>();

        if (hashLength <= 0 || body.Length != hashLength)
        {
            return false;
        }

        verifyData = body.ToArray();
        return true;
    }
}
