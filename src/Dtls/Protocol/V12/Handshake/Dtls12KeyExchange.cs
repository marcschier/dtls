// Copyright (c) marcschier. All rights reserved.
// Licensed under the MIT License. See LICENSE in the project root for license information.

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

    /// <summary>
    /// Parses a bare ServerECDHParams (<c>curve_type=named_curve || named_curve || public</c>),
    /// returning the negotiated curve and public point. Used by the unsigned ECDHE_PSK
    /// ServerKeyExchange.
    /// </summary>
    public static bool TryParseEcdhParams(
        ReadOnlySpan<byte> body,
        out ushort namedCurve,
        out byte[] publicPoint)
    {
        namedCurve = 0;
        publicPoint = Array.Empty<byte>();

        SpanReader reader = new(body);
        if (!reader.TryReadByte(out byte curveType)
            || curveType != NamedCurveType
            || !reader.TryReadUInt16(out namedCurve)
            || !reader.TryReadVector8(out ReadOnlySpan<byte> point)
            || point.Length == 0)
        {
            return false;
        }

        publicPoint = point.ToArray();
        return true;
    }

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
/// For the PSK suites it carries the <c>psk_identity&lt;0..2^16-1&gt;</c> (RFC 4279), optionally
/// followed by the ECDHE point for the ECDHE_PSK suites (RFC 5489).
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

    /// <summary>
    /// Encodes a plain-PSK ClientKeyExchange: <c>psk_identity&lt;0..2^16-1&gt;</c>.
    /// </summary>
    public static byte[] EncodePsk(ReadOnlySpan<byte> identity)
    {
        TlsWriter writer = new(2 + identity.Length);
        int start = writer.BeginVector16();
        writer.WriteBytes(identity);
        writer.EndVector16(start);
        return writer.ToArray();
    }

    public static bool TryParsePsk(ReadOnlySpan<byte> body, out byte[] identity)
    {
        identity = Array.Empty<byte>();
        SpanReader reader = new(body);
        if (!reader.TryReadVector16(out ReadOnlySpan<byte> value) || reader.Remaining != 0)
        {
            return false;
        }

        identity = value.ToArray();
        return true;
    }

    /// <summary>
    /// Encodes an ECDHE_PSK ClientKeyExchange (RFC 5489 section 2):
    /// <c>psk_identity&lt;0..2^16-1&gt; || ecdh_Yc&lt;1..255&gt;</c>.
    /// </summary>
    public static byte[] EncodeEcdhePsk(ReadOnlySpan<byte> identity, ReadOnlySpan<byte> publicPoint)
    {
        TlsWriter writer = new(4 + identity.Length + publicPoint.Length);
        int identityStart = writer.BeginVector16();
        writer.WriteBytes(identity);
        writer.EndVector16(identityStart);
        int pointStart = writer.BeginVector8();
        writer.WriteBytes(publicPoint);
        writer.EndVector8(pointStart);
        return writer.ToArray();
    }

    public static bool TryParseEcdhePsk(
        ReadOnlySpan<byte> body,
        out byte[] identity,
        out byte[] publicPoint)
    {
        identity = Array.Empty<byte>();
        publicPoint = Array.Empty<byte>();
        SpanReader reader = new(body);
        if (!reader.TryReadVector16(out ReadOnlySpan<byte> id)
            || !reader.TryReadVector8(out ReadOnlySpan<byte> point)
            || point.Length == 0)
        {
            return false;
        }

        identity = id.ToArray();
        publicPoint = point.ToArray();
        return true;
    }
}

/// <summary>
/// Encoder/decoder for the DTLS 1.2 PSK ServerKeyExchange bodies. For plain PSK (RFC 4279) the
/// body is the optional <c>psk_identity_hint&lt;0..2^16-1&gt;</c>; for ECDHE_PSK (RFC 5489) it is
/// <c>psk_identity_hint&lt;0..2^16-1&gt; || ServerECDHParams</c> (unsigned, unlike the
/// certificate-authenticated ServerKeyExchange).
/// </summary>
internal static class Dtls12PskServerKeyExchange
{
    /// <summary>
    /// Encodes an ECDHE_PSK ServerKeyExchange: identity hint then the ECDHE params.
    /// </summary>
    public static byte[] EncodeEcdhePsk(
        ReadOnlySpan<byte> identityHint,
        ReadOnlySpan<byte> ecdhParams)
    {
        TlsWriter writer = new(2 + identityHint.Length + ecdhParams.Length);
        int hintStart = writer.BeginVector16();
        writer.WriteBytes(identityHint);
        writer.EndVector16(hintStart);
        writer.WriteBytes(ecdhParams);
        return writer.ToArray();
    }

    public static bool TryParseEcdhePsk(
        ReadOnlySpan<byte> body,
        out byte[] identityHint,
        out ushort namedCurve,
        out byte[] publicPoint)
    {
        identityHint = Array.Empty<byte>();
        namedCurve = 0;
        publicPoint = Array.Empty<byte>();

        SpanReader reader = new(body);
        if (!reader.TryReadVector16(out ReadOnlySpan<byte> hint))
        {
            return false;
        }

        identityHint = hint.ToArray();
        ReadOnlySpan<byte> rest = body.Slice(reader.Position);
        if (!Dtls12ServerKeyExchange.TryParseEcdhParams(rest, out namedCurve, out publicPoint))
        {
            return false;
        }

        return true;
    }

    /// <summary>Encodes a plain-PSK ServerKeyExchange carrying only the identity hint.</summary>
    public static byte[] EncodePskHint(ReadOnlySpan<byte> identityHint)
    {
        TlsWriter writer = new(2 + identityHint.Length);
        int hintStart = writer.BeginVector16();
        writer.WriteBytes(identityHint);
        writer.EndVector16(hintStart);
        return writer.ToArray();
    }
}
