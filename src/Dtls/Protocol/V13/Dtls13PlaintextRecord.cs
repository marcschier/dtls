using System;
using System.Buffers.Binary;
using Dtls.Internal;
using Dtls.Protocol.V13.Handshake;

namespace Dtls.Protocol.V13;

/// <summary>
/// Encoder/decoder for unprotected DTLS 1.3 records (DTLSPlaintext, RFC 9147 section 4):
/// <c>content_type(1) || legacy_record_version=0xFEFD(2) || epoch(2) ||
/// sequence_number(uint48) || length(uint16) || fragment</c>. These records carry the
/// epoch-0 ClientHello/ServerHello and plaintext alerts; protected records (epoch &gt;= 2)
/// use the unified header handled by <see cref="Dtls13RecordProtector"/> instead.
/// </summary>
internal static class Dtls13PlaintextRecord
{
    /// <summary>The handshake content type (22).</summary>
    public const byte HandshakeContentType = 22;

    /// <summary>The alert content type (21).</summary>
    public const byte AlertContentType = 21;

    /// <summary>The application_data content type (23).</summary>
    public const byte ApplicationDataContentType = 23;

    /// <summary>The ack content type (26) (RFC 9147 section 7).</summary>
    public const byte AckContentType = 26;

    /// <summary>The fixed DTLSPlaintext header length, in bytes.</summary>
    public const int HeaderLength = 13;

    /// <summary>Serializes one DTLSPlaintext record.</summary>
    /// <param name="contentType">The record content type.</param>
    /// <param name="epoch">The record epoch (0 for unprotected flights).</param>
    /// <param name="sequenceNumber">The 48-bit record sequence number.</param>
    /// <param name="fragment">The record fragment (the plaintext payload).</param>
    /// <returns>The encoded record bytes.</returns>
    public static byte[] Encode(
        byte contentType,
        ushort epoch,
        ulong sequenceNumber,
        ReadOnlySpan<byte> fragment)
    {
        if (fragment.Length > ushort.MaxValue)
        {
            throw new ArgumentException(
                "Fragment is too large for a DTLSPlaintext record.",
                nameof(fragment));
        }

        byte[] record = new byte[HeaderLength + fragment.Length];
        Span<byte> span = record;
        span[0] = contentType;
        BinaryPrimitives.WriteUInt16BigEndian(span.Slice(1, 2), DtlsWireVersion.Dtls12);
        BinaryPrimitives.WriteUInt16BigEndian(span.Slice(3, 2), epoch);
        BinaryHelpers.WriteUInt48BigEndian(span.Slice(5, 6), sequenceNumber);
        BinaryPrimitives.WriteUInt16BigEndian(span.Slice(11, 2), (ushort)fragment.Length);
        fragment.CopyTo(span.Slice(HeaderLength));
        return record;
    }

    /// <summary>
    /// Parses one DTLSPlaintext record from the front of <paramref name="source"/>.
    /// </summary>
    /// <param name="source">The buffer to parse (may contain trailing records).</param>
    /// <param name="contentType">The parsed content type on success.</param>
    /// <param name="epoch">The parsed epoch on success.</param>
    /// <param name="sequenceNumber">The parsed sequence number on success.</param>
    /// <param name="fragment">The parsed fragment slice on success.</param>
    /// <param name="consumed">The total bytes consumed (header + fragment).</param>
    /// <returns><see langword="true"/> when a complete record was parsed.</returns>
    public static bool TryParse(
        ReadOnlySpan<byte> source,
        out byte contentType,
        out ushort epoch,
        out ulong sequenceNumber,
        out ReadOnlySpan<byte> fragment,
        out int consumed)
    {
        contentType = 0;
        epoch = 0;
        sequenceNumber = 0;
        fragment = default;
        consumed = 0;

        SpanReader reader = new(source);
        if (!reader.TryReadByte(out contentType)
            || !reader.TryReadUInt16(out ushort version)
            || version != DtlsWireVersion.Dtls12
            || !reader.TryReadUInt16(out epoch)
            || !reader.TryReadUInt48(out sequenceNumber)
            || !reader.TryReadUInt16(out ushort length)
            || !reader.TryReadBytes(length, out fragment))
        {
            return false;
        }

        consumed = HeaderLength + length;
        return true;
    }
}
