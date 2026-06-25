// Copyright (c) marcschier. All rights reserved.
// Licensed under the MIT License. See LICENSE in the project root for license information.

using System;
using System.Collections.Generic;
using System.Security.Cryptography;
using Dtls.Internal;

namespace Dtls.Protocol.V13.Handshake;

/// <summary>
/// The decoded fields of a DTLS 1.3 ServerHello body (RFC 9147 / RFC 8446 section 4.1.3).
/// A HelloRetryRequest is a ServerHello whose random equals
/// <see cref="HelloRetryRequestRandom"/>.
/// </summary>
internal sealed class ServerHello
{
    /// <summary>The fixed ServerHello random length, in bytes.</summary>
    public const int RandomLength = 32;

    private static readonly byte[] HelloRetryRequestRandomValue = new byte[]
    {
        0xCF, 0x21, 0xAD, 0x74, 0xE5, 0x9A, 0x61, 0x11,
        0xBE, 0x1D, 0x8C, 0x02, 0x1E, 0x65, 0xB8, 0x91,
        0xC2, 0xA2, 0x11, 0x16, 0x7A, 0xBB, 0x8C, 0x5E,
        0x07, 0x9E, 0x09, 0xE2, 0xC8, 0xA8, 0x33, 0x9C,
    };

    /// <summary>
    /// The special SHA-256 random that marks a ServerHello as a HelloRetryRequest
    /// (RFC 8446 section 4.1.3).
    /// </summary>
    public static ReadOnlySpan<byte> HelloRetryRequestRandom => HelloRetryRequestRandomValue;

    /// <summary>The 32-byte ServerHello random.</summary>
    public byte[] Random { get; init; } = Array.Empty<byte>();

    /// <summary>The echoed legacy_session_id (0..32 bytes).</summary>
    public byte[] LegacySessionIdEcho { get; init; } = Array.Empty<byte>();

    /// <summary>The selected cipher suite.</summary>
    public ushort CipherSuite { get; init; }

    /// <summary>The ServerHello extensions, in order.</summary>
    public IReadOnlyList<HandshakeExtension> Extensions { get; init; } =
        Array.Empty<HandshakeExtension>();

    /// <summary>Whether this ServerHello is a HelloRetryRequest.</summary>
    public bool IsHelloRetryRequest =>
        Random is not null && IsHelloRetryRequestRandom(Random);

    /// <summary>
    /// Determines whether <paramref name="random"/> equals the HelloRetryRequest random.
    /// </summary>
    public static bool IsHelloRetryRequestRandom(ReadOnlySpan<byte> random)
    {
        return random.Length == RandomLength
            && CryptographicOperations.FixedTimeEquals(random, HelloRetryRequestRandomValue);
    }

    /// <summary>Encodes the ServerHello body.</summary>
    public byte[] Encode()
    {
        if (Random is null || Random.Length != RandomLength)
        {
            throw new InvalidOperationException("ServerHello random must be 32 bytes.");
        }

        if (LegacySessionIdEcho is null || LegacySessionIdEcho.Length > 32)
        {
            throw new InvalidOperationException("legacy_session_id_echo length out of range.");
        }

        TlsWriter writer = new(128);
        writer.WriteUInt16(DtlsWireVersion.Dtls12);
        writer.WriteBytes(Random);

        int sessionStart = writer.BeginVector8();
        writer.WriteBytes(LegacySessionIdEcho);
        writer.EndVector8(sessionStart);

        writer.WriteUInt16(CipherSuite);
        writer.WriteByte(0x00);

        ExtensionList.Write(writer, Extensions);
        return writer.ToArray();
    }

    /// <summary>Parses a ServerHello body.</summary>
    public static bool TryParse(ReadOnlySpan<byte> body, out ServerHello serverHello)
    {
        serverHello = new ServerHello();

        SpanReader reader = new(body);
        if (!reader.TryReadUInt16(out ushort legacyVersion)
            || legacyVersion != DtlsWireVersion.Dtls12
            || !reader.TryReadBytes(RandomLength, out ReadOnlySpan<byte> random)
            || !reader.TryReadVector8(out ReadOnlySpan<byte> sessionId)
            || sessionId.Length > 32
            || !reader.TryReadUInt16(out ushort cipherSuite)
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

        serverHello = new ServerHello
        {
            Random = random.ToArray(),
            LegacySessionIdEcho = sessionId.ToArray(),
            CipherSuite = cipherSuite,
            Extensions = extensions,
        };

        return true;
    }
}
