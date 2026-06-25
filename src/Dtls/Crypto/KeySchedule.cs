// Copyright (c) marcschier. All rights reserved.
// Licensed under the MIT License. See LICENSE in the project root for license information.

using System;
using System.Buffers.Binary;
using System.Security.Cryptography;
using System.Text;

namespace Dtls.Crypto;

/// <summary>
/// The TLS 1.3 / DTLS 1.3 key-schedule helpers (RFC 8446 section 7.1, reused by
/// RFC 9147). DTLS 1.3 uses the same <c>"tls13 "</c> label prefix and the same
/// HKDF-Expand-Label / Derive-Secret construction as TLS 1.3.
/// </summary>
internal static class KeySchedule
{
    private static readonly byte[] LabelPrefix = Encoding.ASCII.GetBytes("tls13 ");

    /// <summary>
    /// Encodes the <c>HkdfLabel</c> structure used by HKDF-Expand-Label.
    /// </summary>
    /// <remarks>
    /// <code>
    /// struct {
    ///     uint16 length = Length;
    ///     opaque label&lt;7..255&gt; = "tls13 " + Label;
    ///     opaque context&lt;0..255&gt; = Context;
    /// } HkdfLabel;
    /// </code>
    /// </remarks>
    public static byte[] EncodeHkdfLabel(
        int length,
        ReadOnlySpan<byte> label,
        ReadOnlySpan<byte> context)
    {
        if (length is < 0 or > ushort.MaxValue)
        {
            throw new ArgumentOutOfRangeException(nameof(length));
        }

        int fullLabelLength = LabelPrefix.Length + label.Length;
        if (fullLabelLength is < 7 or > 255)
        {
            throw new ArgumentException("Label length out of range.", nameof(label));
        }

        if (context.Length > 255)
        {
            throw new ArgumentException("Context length out of range.", nameof(context));
        }

        int total = 2 + 1 + fullLabelLength + 1 + context.Length;
        byte[] result = new byte[total];
        Span<byte> span = result;

        BinaryPrimitives.WriteUInt16BigEndian(span, (ushort)length);
        span[2] = (byte)fullLabelLength;
        LabelPrefix.CopyTo(span.Slice(3));
        label.CopyTo(span.Slice(3 + LabelPrefix.Length));
        int contextLengthOffset = 3 + fullLabelLength;
        span[contextLengthOffset] = (byte)context.Length;
        context.CopyTo(span.Slice(contextLengthOffset + 1));

        return result;
    }

    /// <summary>HKDF-Expand-Label(Secret, Label, Context, Length).</summary>
    public static byte[] ExpandLabel(
        HashAlgorithmName hash,
        ReadOnlySpan<byte> secret,
        ReadOnlySpan<byte> label,
        ReadOnlySpan<byte> context,
        int length)
    {
        byte[] hkdfLabel = EncodeHkdfLabel(length, label, context);
        return Hkdf.Expand(hash, secret, hkdfLabel, length);
    }

    /// <summary>
    /// Derive-Secret(Secret, Label, Messages) = HKDF-Expand-Label(Secret, Label,
    /// Transcript-Hash(Messages), Hash.length).
    /// </summary>
    public static byte[] DeriveSecret(
        HashAlgorithmName hash,
        ReadOnlySpan<byte> secret,
        ReadOnlySpan<byte> label,
        ReadOnlySpan<byte> transcriptHash)
    {
        return ExpandLabel(hash, secret, label, transcriptHash, Hkdf.HashLength(hash));
    }

    /// <summary>
    /// Computes the Early Secret = HKDF-Extract(0, PSK). When no PSK is supplied a
    /// string of <c>Hash.length</c> zero bytes is used, as in the (EC)DHE-only handshake.
    /// </summary>
    public static byte[] EarlySecret(HashAlgorithmName hash, ReadOnlySpan<byte> presharedKey)
    {
        int hashLength = Hkdf.HashLength(hash);
        if (presharedKey.IsEmpty)
        {
            Span<byte> zeros = stackalloc byte[hashLength];
            zeros.Clear();
            return Hkdf.Extract(hash, ReadOnlySpan<byte>.Empty, zeros);
        }

        return Hkdf.Extract(hash, ReadOnlySpan<byte>.Empty, presharedKey);
    }

    /// <summary>
    /// Advances the schedule from one stage's secret to the next using the
    /// <c>"derived"</c> label over an empty-message transcript hash, then
    /// HKDF-Extract with the supplied input keying material.
    /// </summary>
    public static byte[] DeriveNext(
        HashAlgorithmName hash,
        ReadOnlySpan<byte> secret,
        ReadOnlySpan<byte> inputKeyingMaterial)
    {
        int hashLength = Hkdf.HashLength(hash);
        Span<byte> emptyHash = stackalloc byte[hashLength];
        HashEmpty(hash, emptyHash);

        byte[] derived = DeriveSecret(hash, secret, DerivedLabel, emptyHash);

        if (inputKeyingMaterial.IsEmpty)
        {
            Span<byte> zeros = stackalloc byte[hashLength];
            zeros.Clear();
            byte[] next = Hkdf.Extract(hash, derived, zeros);
            CryptographicOperations.ZeroMemory(derived);
            return next;
        }

        byte[] result = Hkdf.Extract(hash, derived, inputKeyingMaterial);
        CryptographicOperations.ZeroMemory(derived);
        return result;
    }

    private static readonly byte[] DerivedLabel = Encoding.ASCII.GetBytes("derived");

    private static void HashEmpty(HashAlgorithmName hash, Span<byte> destination)
    {
        using IncrementalHash digest = IncrementalHash.CreateHash(hash);
        byte[] result = digest.GetHashAndReset();
        result.CopyTo(destination);
    }
}
