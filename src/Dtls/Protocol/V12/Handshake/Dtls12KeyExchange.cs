using System;
using Dtls.Internal;

namespace Dtls.Protocol.V12.Handshake;

/// <summary>
/// Encoder/decoder for the DTLS 1.2 ServerKeyExchange body for the (EC)DHE key exchanges
/// (RFC 4492 / RFC 8422 section 5.4). The <c>ServerECDHParams</c> are
/// <c>curve_type(1)=named_curve(3) || named_curve(2) || public&lt;1..255&gt;</c>; for the
/// certificate-authenticated suites they are followed by
/// <c>SignatureAndHashAlgorithm(2) || signature&lt;0..2^16-1&gt;</c> over
/// <c>client_random || server_random || ServerECDHParams</c>.
/// </summary>
internal static class Dtls12ServerKeyExchange
{
    private const byte NamedCurveType = 0x03;

    /// <summary>Encodes the ServerECDHParams (the bytes that are also signed).</summary>
    public static byte[] EncodeEcdhParams(ushort namedCurve, ReadOnlySpan<byte> publicPoint)
    {
        TlsWriter writer = new(8 + publicPoint.Length);
        writer.WriteByte(NamedCurveType);
        writer.WriteUInt16(namedCurve);
        int start = writer.BeginVector8();
        writer.WriteBytes(publicPoint);
        writer.EndVector8(start);
        return writer.ToArray();
    }

    /// <summary>Encodes a signed (certificate-authenticated) ServerKeyExchange body.</summary>
    public static byte[] EncodeSigned(
        ReadOnlySpan<byte> ecdhParams,
        ushort signatureAlgorithm,
        ReadOnlySpan<byte> signature)
    {
        TlsWriter writer = new(ecdhParams.Length + 8 + signature.Length);
        writer.WriteBytes(ecdhParams);
        writer.WriteUInt16(signatureAlgorithm);
        int start = writer.BeginVector16();
        writer.WriteBytes(signature);
        writer.EndVector16(start);
        return writer.ToArray();
    }

    /// <summary>
    /// Parses a signed ServerKeyExchange body, returning the negotiated curve and public point, the
    /// signature algorithm and signature, and the raw ServerECDHParams bytes (for verifying the
    /// signature over <c>client_random || server_random || ServerECDHParams</c>).
    /// </summary>
    public static bool TryParseSigned(
        ReadOnlySpan<byte> body,
        out ushort namedCurve,
        out byte[] publicPoint,
        out ushort signatureAlgorithm,
        out byte[] signature,
        out byte[] ecdhParams)
    {
        namedCurve = 0;
        publicPoint = Array.Empty<byte>();
        signatureAlgorithm = 0;
        signature = Array.Empty<byte>();
        ecdhParams = Array.Empty<byte>();

        SpanReader reader = new(body);
        if (!reader.TryReadByte(out byte curveType)
            || curveType != NamedCurveType
            || !reader.TryReadUInt16(out namedCurve)
            || !reader.TryReadVector8(out ReadOnlySpan<byte> point)
            || point.Length == 0)
        {
            return false;
        }

        int paramsLength = reader.Position;
        ecdhParams = body.Slice(0, paramsLength).ToArray();
        publicPoint = point.ToArray();

        if (!reader.TryReadUInt16(out signatureAlgorithm)
            || !reader.TryReadVector16(out ReadOnlySpan<byte> sig))
        {
            return false;
        }

        signature = sig.ToArray();
        return true;
    }
}

/// <summary>
/// Encoder/decoder for the DTLS 1.2 ClientKeyExchange body (RFC 4492 / RFC 8422 section 5.7):
/// for the ECDHE suites the body is the client's ephemeral EC point <c>public&lt;1..255&gt;</c>.
/// </summary>
internal static class Dtls12ClientKeyExchange
{
    public static byte[] EncodeEcdhe(ReadOnlySpan<byte> publicPoint)
    {
        TlsWriter writer = new(2 + publicPoint.Length);
        int start = writer.BeginVector8();
        writer.WriteBytes(publicPoint);
        writer.EndVector8(start);
        return writer.ToArray();
    }

    public static bool TryParseEcdhe(ReadOnlySpan<byte> body, out byte[] publicPoint)
    {
        publicPoint = Array.Empty<byte>();
        SpanReader reader = new(body);
        if (!reader.TryReadVector8(out ReadOnlySpan<byte> point) || point.Length == 0)
        {
            return false;
        }

        publicPoint = point.ToArray();
        return true;
    }
}
