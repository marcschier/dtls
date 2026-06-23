using System;
using Dtls.Internal;

namespace Dtls.Protocol.V13.Handshake;

/// <summary>
/// The parsed fields of a DTLS 1.3 handshake message header (RFC 9147 section 5.2):
/// <c>msg_type(1) || length(uint24) || message_seq(uint16) || fragment_offset(uint24) ||
/// fragment_length(uint24)</c>.
/// </summary>
internal readonly struct HandshakeMessageHeader
{
    /// <summary>The handshake message type.</summary>
    public HandshakeType MessageType { get; init; }

    /// <summary>The total length of the (reassembled) handshake message body.</summary>
    public int Length { get; init; }

    /// <summary>The handshake message sequence number.</summary>
    public ushort MessageSequence { get; init; }

    /// <summary>The byte offset of this fragment within the full message body.</summary>
    public int FragmentOffset { get; init; }

    /// <summary>The length of this fragment's slice of the message body.</summary>
    public int FragmentLength { get; init; }
}

/// <summary>
/// Encoder/decoder for DTLS 1.3 handshake messages (RFC 9147 section 5.2). Handles the
/// fragmenting handshake header and full (unfragmented) message (de)serialization. The
/// transcript hash uses the TLS 1.3 message layout (without the DTLS fragment fields);
/// see <see cref="WriteTranscriptBytes"/>.
/// </summary>
internal static class HandshakeMessage
{
    /// <summary>The fixed DTLS handshake header length, in bytes.</summary>
    public const int HeaderLength = 12;

    /// <summary>Writes a DTLS handshake header into <paramref name="writer"/>.</summary>
    public static void WriteHeader(
        TlsWriter writer,
        HandshakeType messageType,
        int length,
        ushort messageSequence,
        int fragmentOffset,
        int fragmentLength)
    {
        if (writer is null)
        {
            throw new ArgumentNullException(nameof(writer));
        }

        if (length is < 0 or > 0xFFFFFF)
        {
            throw new ArgumentOutOfRangeException(nameof(length));
        }

        if (fragmentOffset is < 0 or > 0xFFFFFF)
        {
            throw new ArgumentOutOfRangeException(nameof(fragmentOffset));
        }

        if (fragmentLength is < 0 or > 0xFFFFFF)
        {
            throw new ArgumentOutOfRangeException(nameof(fragmentLength));
        }

        writer.WriteByte((byte)messageType);
        writer.WriteUInt24((uint)length);
        writer.WriteUInt16(messageSequence);
        writer.WriteUInt24((uint)fragmentOffset);
        writer.WriteUInt24((uint)fragmentLength);
    }

    /// <summary>
    /// Serializes a complete, unfragmented handshake message (fragment_offset = 0,
    /// fragment_length = length) with <paramref name="body"/> as its body.
    /// </summary>
    public static byte[] Serialize(
        HandshakeType messageType,
        ushort messageSequence,
        ReadOnlySpan<byte> body)
    {
        TlsWriter writer = new(HeaderLength + body.Length);
        WriteHeader(writer, messageType, body.Length, messageSequence, 0, body.Length);
        writer.WriteBytes(body);
        return writer.ToArray();
    }

    /// <summary>Parses a DTLS handshake header from <paramref name="source"/>.</summary>
    public static bool TryParseHeader(
        ReadOnlySpan<byte> source,
        out HandshakeMessageHeader header)
    {
        header = default;

        SpanReader reader = new(source);
        if (!reader.TryReadByte(out byte type)
            || !reader.TryReadUInt24(out uint length)
            || !reader.TryReadUInt16(out ushort messageSequence)
            || !reader.TryReadUInt24(out uint fragmentOffset)
            || !reader.TryReadUInt24(out uint fragmentLength))
        {
            return false;
        }

        header = new HandshakeMessageHeader
        {
            MessageType = (HandshakeType)type,
            Length = (int)length,
            MessageSequence = messageSequence,
            FragmentOffset = (int)fragmentOffset,
            FragmentLength = (int)fragmentLength,
        };

        return true;
    }

    /// <summary>
    /// Parses a complete, single-fragment handshake message (fragment_offset = 0 and
    /// fragment_length = length) and returns its header and body slice.
    /// </summary>
    public static bool TryParse(
        ReadOnlySpan<byte> source,
        out HandshakeMessageHeader header,
        out ReadOnlySpan<byte> body)
    {
        body = default;

        if (!TryParseHeader(source, out header))
        {
            return false;
        }

        if (header.FragmentOffset != 0 || header.FragmentLength != header.Length)
        {
            return false;
        }

        if (source.Length < HeaderLength + header.Length)
        {
            return false;
        }

        body = source.Slice(HeaderLength, header.Length);
        return true;
    }

    /// <summary>
    /// Writes the TLS 1.3 reconstructed handshake bytes used by the transcript hash
    /// (RFC 9147 section 5.2): <c>msg_type(1) || length(uint24) || body</c>, i.e. the
    /// DTLS message_seq and fragment fields are omitted.
    /// </summary>
    public static void WriteTranscriptBytes(
        TlsWriter writer,
        HandshakeType messageType,
        ReadOnlySpan<byte> body)
    {
        if (writer is null)
        {
            throw new ArgumentNullException(nameof(writer));
        }

        if (body.Length > 0xFFFFFF)
        {
            throw new ArgumentOutOfRangeException(nameof(body));
        }

        writer.WriteByte((byte)messageType);
        writer.WriteUInt24((uint)body.Length);
        writer.WriteBytes(body);
    }

    /// <summary>
    /// Returns the TLS 1.3 reconstructed handshake bytes (see
    /// <see cref="WriteTranscriptBytes"/>) for <paramref name="body"/>.
    /// </summary>
    public static byte[] ToTranscriptBytes(HandshakeType messageType, ReadOnlySpan<byte> body)
    {
        TlsWriter writer = new(4 + body.Length);
        WriteTranscriptBytes(writer, messageType, body);
        return writer.ToArray();
    }
}
