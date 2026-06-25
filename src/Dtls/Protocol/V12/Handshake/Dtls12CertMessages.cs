// Copyright (c) marcschier. All rights reserved.
// Licensed under the MIT License. See LICENSE in the project root for license information.

using System;
using System.Collections.Generic;
using Dtls.Internal;

namespace Dtls.Protocol.V12.Handshake;

/// <summary>
/// Encoder/decoder for the DTLS 1.2 Certificate body (RFC 5246 section 7.4.2):
/// <c>certificate_list&lt;0..2^24-1&gt;</c> where each entry is
/// <c>opaque cert&lt;1..2^24-1&gt;</c>. For Raw Public Keys (RFC 7250) the single entry is a
/// SubjectPublicKeyInfo.
/// </summary>
internal static class Dtls12Certificate
{
    public static byte[] Encode(IReadOnlyList<byte[]> certificates)
    {
        TlsWriter writer = new(256);
        int listStart = writer.BeginVector24();
        foreach (byte[] certificate in certificates)
        {
            int entryStart = writer.BeginVector24();
            writer.WriteBytes(certificate);
            writer.EndVector24(entryStart);
        }

        writer.EndVector24(listStart);
        return writer.ToArray();
    }

    public static bool TryParse(ReadOnlySpan<byte> body, out List<byte[]> certificates)
    {
        certificates = new List<byte[]>();
        SpanReader reader = new(body);
        if (!reader.TryReadVector24(out ReadOnlySpan<byte> list) || reader.Remaining != 0)
        {
            return false;
        }

        SpanReader inner = new(list);
        while (inner.Remaining > 0)
        {
            if (!inner.TryReadVector24(out ReadOnlySpan<byte> entry))
            {
                certificates = new List<byte[]>();
                return false;
            }

            certificates.Add(entry.ToArray());
        }

        return true;
    }
}

/// <summary>
/// Encoder/decoder for the DTLS 1.2 CertificateRequest body (RFC 5246 section 7.4.4):
/// <c>certificate_types&lt;1..255&gt; || supported_signature_algorithms&lt;2..2^16-2&gt; ||
/// certificate_authorities&lt;0..2^16-1&gt;</c>. The certificate authorities list is left empty.
/// </summary>
internal static class Dtls12CertificateRequest
{
    /// <summary>ecdsa_sign client certificate type (RFC 4492).</summary>
    public const byte EcdsaSign = 64;

    /// <summary>rsa_sign client certificate type (RFC 5246).</summary>
    public const byte RsaSign = 1;

    public static byte[] Encode(
        IReadOnlyList<byte> certificateTypes,
        IReadOnlyList<ushort> signatureAlgorithms)
    {
        TlsWriter writer = new(32);

        int typesStart = writer.BeginVector8();
        foreach (byte type in certificateTypes)
        {
            writer.WriteByte(type);
        }

        writer.EndVector8(typesStart);

        int algsStart = writer.BeginVector16();
        foreach (ushort alg in signatureAlgorithms)
        {
            writer.WriteUInt16(alg);
        }

        writer.EndVector16(algsStart);

        // certificate_authorities<0..2^16-1>: empty.
        writer.WriteUInt16(0);
        return writer.ToArray();
    }

    public static bool TryParse(
        ReadOnlySpan<byte> body,
        out List<byte> certificateTypes,
        out List<ushort> signatureAlgorithms)
    {
        certificateTypes = new List<byte>();
        signatureAlgorithms = new List<ushort>();

        SpanReader reader = new(body);
        if (!reader.TryReadVector8(out ReadOnlySpan<byte> types)
            || types.Length == 0
            || !reader.TryReadVector16(out ReadOnlySpan<byte> algs)
            || (algs.Length % 2) != 0
            || !reader.TryReadVector16(out _))
        {
            return false;
        }

        foreach (byte type in types)
        {
            certificateTypes.Add(type);
        }

        for (int i = 0; i < algs.Length; i += 2)
        {
            signatureAlgorithms.Add((ushort)((algs[i] << 8) | algs[i + 1]));
        }

        return true;
    }
}

/// <summary>
/// Encoder/decoder for the DTLS 1.2 CertificateVerify body (RFC 5246 section 7.4.8):
/// <c>SignatureAndHashAlgorithm(2) || signature&lt;0..2^16-1&gt;</c> over
/// <c>Hash(handshake_messages)</c>.
/// </summary>
internal static class Dtls12CertificateVerify
{
    public static byte[] Encode(ushort signatureAlgorithm, ReadOnlySpan<byte> signature)
    {
        TlsWriter writer = new(8 + signature.Length);
        writer.WriteUInt16(signatureAlgorithm);
        int start = writer.BeginVector16();
        writer.WriteBytes(signature);
        writer.EndVector16(start);
        return writer.ToArray();
    }

    public static bool TryParse(
        ReadOnlySpan<byte> body,
        out ushort signatureAlgorithm,
        out byte[] signature)
    {
        signatureAlgorithm = 0;
        signature = Array.Empty<byte>();

        SpanReader reader = new(body);
        if (!reader.TryReadUInt16(out signatureAlgorithm)
            || !reader.TryReadVector16(out ReadOnlySpan<byte> sig)
            || reader.Remaining != 0)
        {
            return false;
        }

        signature = sig.ToArray();
        return true;
    }
}
