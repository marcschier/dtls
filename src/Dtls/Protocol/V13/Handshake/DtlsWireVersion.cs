// Copyright (c) marcschier. All rights reserved.
// Licensed under the MIT License. See LICENSE in the project root for license information.

namespace Dtls.Protocol.V13.Handshake;

/// <summary>
/// The on-the-wire <c>ProtocolVersion</c> constants used by DTLS 1.3 handshake messages.
/// </summary>
internal static class DtlsWireVersion
{
    /// <summary>The legacy_version value used in record/hello headers: DTLS 1.2 (0xFEFD).</summary>
    public const ushort Dtls12 = 0xFEFD;

    /// <summary>The DTLS 1.3 version advertised in supported_versions (0xFEFC).</summary>
    public const ushort Dtls13 = 0xFEFC;
}
