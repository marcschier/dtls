using System;
using System.Collections.Generic;
using Dtls.Internal;
using Dtls.Protocol.V13.Handshake;

namespace Dtls.Protocol.V12.Handshake;

/// <summary>
/// Encoder/decoder for the DTLS 1.2 ClientHello body (RFC 6347 section 4.2.1, RFC 5246
/// section 7.4.1.2): <c>client_version || random(32) || session_id&lt;0..32&gt; ||
/// cookie&lt;0..255&gt; || cipher_suites&lt;2..2^16-2&gt; || compression_methods&lt;1..255&gt; ||
/// extensions&lt;0..2^16-1&gt;</c>. The DTLS-specific <c>cookie</c> field carries the
/// HelloVerifyRequest token on the second ClientHello.
/// </summary>
internal sealed class Dtls12ClientHello
{
    /// <summary>The fixed ClientHello/ServerHello random length, in bytes.</summary>
    public const int RandomLength = 32;

    public byte[] Random { get; init; } = Array.Empty<byte>();

    public byte[] SessionId { get; init; } = Array.Empty<byte>();

    public byte[] Cookie { get; init; } = Array.Empty<byte>();

    public ushort[] CipherSuites { get; init; } = Array.Empty<ushort>();

    public IReadOnlyList<HandshakeExtension> Extensions { get; init; } =
        Array.Empty<HandshakeExtension>();

    /// <summary>Encodes the ClientHello body.</summary>
    public byte[] Encode()
    {
        if (Random is null || Random.Length != RandomLength)
        {
            throw new InvalidOperationException("ClientHello random must be 32 bytes.");
        }

        TlsWriter writer = new(128);
        writer.WriteUInt16(DtlsWireVersion.Dtls12);
        writer.WriteBytes(Random);

        int sessionStart = writer.BeginVector8();
        writer.WriteBytes(SessionId);
        writer.EndVector8(sessionStart);

        int cookieStart = writer.BeginVector8();
        writer.WriteBytes(Cookie);
        writer.EndVector8(cookieStart);

        int suitesStart = writer.BeginVector16();
        foreach (ushort suite in CipherSuites)
        {
            writer.WriteUInt16(suite);
        }

        writer.EndVector16(suitesStart);

        // compression_methods: only the null method (0).
        int compressionStart = writer.BeginVector8();
        writer.WriteByte(0);
        writer.EndVector8(compressionStart);

        ExtensionList.Write(writer, Extensions);
        return writer.ToArray();
    }

    /// <summary>Parses a ClientHello body.</summary>
    public static bool TryParse(ReadOnlySpan<byte> body, out Dtls12ClientHello clientHello)
    {
        clientHello = new Dtls12ClientHello();

        SpanReader reader = new(body);
        if (!reader.TryReadUInt16(out ushort version)
            || version != DtlsWireVersion.Dtls12
            || !reader.TryReadBytes(RandomLength, out ReadOnlySpan<byte> random)
            || !reader.TryReadVector8(out ReadOnlySpan<byte> sessionId)
            || sessionId.Length > 32
            || !reader.TryReadVector8(out ReadOnlySpan<byte> cookie)
            || !reader.TryReadVector16(out ReadOnlySpan<byte> suiteBytes)
            || (suiteBytes.Length % 2) != 0
            || !reader.TryReadVector8(out ReadOnlySpan<byte> compression)
            || compression.Length == 0)
        {
            return false;
        }

        ushort[] suites = new ushort[suiteBytes.Length / 2];
        for (int i = 0; i < suites.Length; i++)
        {
            suites[i] = (ushort)((suiteBytes[i * 2] << 8) | suiteBytes[(i * 2) + 1]);
        }

        List<HandshakeExtension> extensions = new();
        if (reader.Remaining > 0
            && !ExtensionList.TryParse(body.Slice(reader.Position), out extensions))
        {
            return false;
        }

        clientHello = new Dtls12ClientHello
        {
            Random = random.ToArray(),
            SessionId = sessionId.ToArray(),
            Cookie = cookie.ToArray(),
            CipherSuites = suites,
            Extensions = extensions,
        };
        return true;
    }
}

/// <summary>
/// Encoder/decoder for the DTLS 1.2 HelloVerifyRequest body (RFC 6347 section 4.2.1):
/// <c>server_version || cookie&lt;0..255&gt;</c>. The server returns it (stateless) so the client
/// proves return-routability by echoing the cookie in a second ClientHello.
/// </summary>
internal static class Dtls12HelloVerifyRequest
{
    public static byte[] Encode(ReadOnlySpan<byte> cookie)
    {
        TlsWriter writer = new(8 + cookie.Length);
        writer.WriteUInt16(DtlsWireVersion.Dtls12);
        int cookieStart = writer.BeginVector8();
        writer.WriteBytes(cookie);
        writer.EndVector8(cookieStart);
        return writer.ToArray();
    }

    public static bool TryParse(ReadOnlySpan<byte> body, out byte[] cookie)
    {
        cookie = Array.Empty<byte>();
        SpanReader reader = new(body);
        if (!reader.TryReadUInt16(out _)
            || !reader.TryReadVector8(out ReadOnlySpan<byte> value))
        {
            return false;
        }

        cookie = value.ToArray();
        return true;
    }
}

/// <summary>
/// Encoder/decoder for the DTLS 1.2 ServerHello body (RFC 5246 section 7.4.1.3):
/// <c>server_version || random(32) || session_id&lt;0..32&gt; || cipher_suite ||
/// compression_method || extensions&lt;0..2^16-1&gt;</c>.
/// </summary>
internal sealed class Dtls12ServerHello
{
    public byte[] Random { get; init; } = Array.Empty<byte>();

    public byte[] SessionId { get; init; } = Array.Empty<byte>();

    public ushort CipherSuite { get; init; }

    public IReadOnlyList<HandshakeExtension> Extensions { get; init; } =
        Array.Empty<HandshakeExtension>();

    public byte[] Encode()
    {
        if (Random is null || Random.Length != Dtls12ClientHello.RandomLength)
        {
            throw new InvalidOperationException("ServerHello random must be 32 bytes.");
        }

        TlsWriter writer = new(96);
        writer.WriteUInt16(DtlsWireVersion.Dtls12);
        writer.WriteBytes(Random);

        int sessionStart = writer.BeginVector8();
        writer.WriteBytes(SessionId);
        writer.EndVector8(sessionStart);

        writer.WriteUInt16(CipherSuite);
        writer.WriteByte(0); // compression_method = null

        ExtensionList.Write(writer, Extensions);
        return writer.ToArray();
    }

    public static bool TryParse(ReadOnlySpan<byte> body, out Dtls12ServerHello serverHello)
    {
        serverHello = new Dtls12ServerHello();

        SpanReader reader = new(body);
        if (!reader.TryReadUInt16(out ushort version)
            || version != DtlsWireVersion.Dtls12
            || !reader.TryReadBytes(Dtls12ClientHello.RandomLength, out ReadOnlySpan<byte> random)
            || !reader.TryReadVector8(out ReadOnlySpan<byte> sessionId)
            || sessionId.Length > 32
            || !reader.TryReadUInt16(out ushort cipherSuite)
            || !reader.TryReadByte(out byte compression)
            || compression != 0)
        {
            return false;
        }

        List<HandshakeExtension> extensions = new();
        if (reader.Remaining > 0
            && !ExtensionList.TryParse(body.Slice(reader.Position), out extensions))
        {
            return false;
        }

        serverHello = new Dtls12ServerHello
        {
            Random = random.ToArray(),
            SessionId = sessionId.ToArray(),
            CipherSuite = cipherSuite,
            Extensions = extensions,
        };
        return true;
    }
}
