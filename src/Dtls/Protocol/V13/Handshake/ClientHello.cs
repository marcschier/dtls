// Copyright (c) marcschier. All rights reserved.
// Licensed under the MIT License. See LICENSE in the project root for license information.

using System;
using System.Collections.Generic;
using Dtls.Internal;

namespace Dtls.Protocol.V13.Handshake;

/// <summary>
/// The decoded fields of a DTLS 1.3 ClientHello body (RFC 9147 / RFC 8446 section 4.1.2).
/// </summary>
internal sealed class ClientHello
{
    /// <summary>The fixed ClientHello random length, in bytes.</summary>
    public const int RandomLength = 32;

    /// <summary>The 32-byte ClientHello random.</summary>
    public byte[] Random { get; init; } = Array.Empty<byte>();

    /// <summary>The legacy_session_id (empty in DTLS 1.3, 0..32 bytes).</summary>
    public byte[] LegacySessionId { get; init; } = Array.Empty<byte>();

    /// <summary>The DTLS cookie field (usually empty, 0..255 bytes).</summary>
    public byte[] Cookie { get; init; } = Array.Empty<byte>();

    /// <summary>The offered cipher suites, in preference order.</summary>
    public IReadOnlyList<ushort> CipherSuites { get; init; } = Array.Empty<ushort>();

    /// <summary>The ClientHello extensions, in order.</summary>
    public IReadOnlyList<HandshakeExtension> Extensions { get; init; } =
        Array.Empty<HandshakeExtension>();

    /// <summary>Encodes the ClientHello body.</summary>
    public byte[] Encode()
    {
        if (Random is null || Random.Length != RandomLength)
        {
            throw new InvalidOperationException("ClientHello random must be 32 bytes.");
        }

        if (LegacySessionId is null || LegacySessionId.Length > 32)
        {
            throw new InvalidOperationException("legacy_session_id length out of range.");
        }

        if (Cookie is null || Cookie.Length > 0xFF)
        {
            throw new InvalidOperationException("cookie length out of range.");
        }

        if (CipherSuites is null || CipherSuites.Count == 0)
        {
            throw new InvalidOperationException("At least one cipher suite is required.");
        }

        TlsWriter writer = new(128);
        writer.WriteUInt16(DtlsWireVersion.Dtls12);
        writer.WriteBytes(Random);

        int sessionStart = writer.BeginVector8();
        writer.WriteBytes(LegacySessionId);
        writer.EndVector8(sessionStart);

        int cookieStart = writer.BeginVector8();
        writer.WriteBytes(Cookie);
        writer.EndVector8(cookieStart);

        int suitesStart = writer.BeginVector16();
        for (int i = 0; i < CipherSuites.Count; i++)
        {
            writer.WriteUInt16(CipherSuites[i]);
        }

        writer.EndVector16(suitesStart);

        writer.WriteByte(0x01);
        writer.WriteByte(0x00);

        ExtensionList.Write(writer, Extensions);
        return writer.ToArray();
    }

    /// <summary>Parses a ClientHello body.</summary>
    public static bool TryParse(ReadOnlySpan<byte> body, out ClientHello clientHello)
    {
        clientHello = new ClientHello();

        SpanReader reader = new(body);
        if (!reader.TryReadUInt16(out ushort legacyVersion)
            || legacyVersion != DtlsWireVersion.Dtls12
            || !reader.TryReadBytes(RandomLength, out ReadOnlySpan<byte> random)
            || !reader.TryReadVector8(out ReadOnlySpan<byte> sessionId)
            || sessionId.Length > 32
            || !reader.TryReadVector8(out ReadOnlySpan<byte> cookie)
            || !reader.TryReadVector16(out ReadOnlySpan<byte> suiteBytes))
        {
            return false;
        }

        if ((suiteBytes.Length % 2) != 0 || suiteBytes.IsEmpty)
        {
            return false;
        }

        List<ushort> suites = new();
        SpanReader suiteReader = new(suiteBytes);
        while (suiteReader.TryReadUInt16(out ushort suite))
        {
            suites.Add(suite);
        }

        if (!reader.TryReadByte(out byte compressionLength)
            || compressionLength != 1
            || !reader.TryReadByte(out byte compression)
            || compression != 0)
        {
            return false;
        }

        if (!ExtensionList.TryParse(
                body.Slice(reader.Position),
                out List<HandshakeExtension> extensions))
        {
            return false;
        }

        clientHello = new ClientHello
        {
            Random = random.ToArray(),
            LegacySessionId = sessionId.ToArray(),
            Cookie = cookie.ToArray(),
            CipherSuites = suites,
            Extensions = extensions,
        };

        return true;
    }
}
