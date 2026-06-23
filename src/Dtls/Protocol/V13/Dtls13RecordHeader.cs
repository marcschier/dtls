using System;
using System.Buffers.Binary;

namespace Dtls.Protocol.V13;

/// <summary>
/// The parsed fields of a DTLS 1.3 unified record header (RFC 9147 section 4.1).
/// </summary>
internal readonly struct Dtls13RecordHeaderInfo
{
    /// <summary>The header's first byte (the <c>0b001CSLEE</c> flags octet).</summary>
    public byte FirstByte { get; init; }

    /// <summary>The low two bits of the epoch carried by the header.</summary>
    public int EpochLowBits { get; init; }

    /// <summary>Whether a Connection ID is present in the header.</summary>
    public bool ConnectionIdPresent { get; init; }

    /// <summary>The offset of the Connection ID within the record.</summary>
    public int ConnectionIdOffset { get; init; }

    /// <summary>The length of the Connection ID, in bytes.</summary>
    public int ConnectionIdLength { get; init; }

    /// <summary>Whether the on-wire sequence number is 16 bits (else 8 bits).</summary>
    public bool SixteenBitSequenceNumber { get; init; }

    /// <summary>The offset of the (encrypted) sequence number within the record.</summary>
    public int SequenceNumberOffset { get; init; }

    /// <summary>The length of the on-wire sequence number, in bytes (1 or 2).</summary>
    public int SequenceNumberLength { get; init; }

    /// <summary>The on-wire (still encrypted) sequence number value.</summary>
    public ushort EncodedSequenceNumber { get; init; }

    /// <summary>Whether an explicit length field is present.</summary>
    public bool LengthPresent { get; init; }

    /// <summary>The total header length, i.e. the offset of the encrypted record.</summary>
    public int HeaderLength { get; init; }

    /// <summary>The offset of the encrypted record within the record buffer.</summary>
    public int EncryptedRecordOffset { get; init; }

    /// <summary>The length of the encrypted record, in bytes.</summary>
    public int EncryptedRecordLength { get; init; }
}

/// <summary>
/// Encoder/decoder for the DTLS 1.3 unified record header (RFC 9147 section 4.1). The
/// first byte is <c>0b001CSLEE</c>: bits <c>001</c> are fixed, <c>C</c> flags a Connection
/// ID, <c>S</c> selects an 8- or 16-bit sequence number, <c>L</c> flags an explicit length,
/// and <c>EE</c> carries the low two bits of the epoch.
/// </summary>
internal static class Dtls13RecordHeader
{
    /// <summary>Mask selecting the three fixed high bits of the first byte.</summary>
    public const byte FixedBitsMask = 0xE0;

    /// <summary>The required value of the three fixed high bits (<c>001</c>).</summary>
    public const byte FixedBits = 0x20;

    /// <summary>Flag bit indicating a Connection ID is present.</summary>
    public const byte ConnectionIdFlag = 0x10;

    /// <summary>Flag bit indicating a 16-bit (rather than 8-bit) sequence number.</summary>
    public const byte SequenceNumber16Flag = 0x08;

    /// <summary>Flag bit indicating an explicit length field is present.</summary>
    public const byte LengthFlag = 0x04;

    /// <summary>Mask selecting the two epoch bits of the first byte.</summary>
    public const byte EpochMask = 0x03;

    /// <summary>
    /// Computes the header length for the supplied options without writing anything.
    /// </summary>
    /// <param name="connectionIdLength">The Connection ID length (0 when absent).</param>
    /// <param name="sixteenBitSequenceNumber">Whether the sequence number is 16-bit.</param>
    /// <param name="lengthPresent">Whether an explicit length field is included.</param>
    /// <returns>The total header length in bytes.</returns>
    public static int ComputeLength(
        int connectionIdLength,
        bool sixteenBitSequenceNumber,
        bool lengthPresent)
    {
        return 1
            + connectionIdLength
            + (sixteenBitSequenceNumber ? 2 : 1)
            + (lengthPresent ? 2 : 0);
    }

    /// <summary>
    /// Writes a unified record header into <paramref name="destination"/>.
    /// </summary>
    /// <param name="destination">The buffer receiving the header.</param>
    /// <param name="epochLowBits">The low two bits of the epoch.</param>
    /// <param name="connectionId">The Connection ID, or empty when absent.</param>
    /// <param name="sequenceNumber">The on-wire sequence number value.</param>
    /// <param name="sixteenBitSequenceNumber">Whether to emit a 16-bit sequence number.</param>
    /// <param name="lengthPresent">Whether to emit an explicit length field.</param>
    /// <param name="length">The encrypted-record length to emit when present.</param>
    /// <returns>The number of bytes written.</returns>
    public static int Write(
        Span<byte> destination,
        int epochLowBits,
        ReadOnlySpan<byte> connectionId,
        ushort sequenceNumber,
        bool sixteenBitSequenceNumber,
        bool lengthPresent,
        ushort length)
    {
        int required = ComputeLength(
            connectionId.Length,
            sixteenBitSequenceNumber,
            lengthPresent);
        if (destination.Length < required)
        {
            throw new ArgumentException(
                "Destination is too small for the header.",
                nameof(destination));
        }

        byte first = FixedBits;
        if (!connectionId.IsEmpty)
        {
            first |= ConnectionIdFlag;
        }

        if (sixteenBitSequenceNumber)
        {
            first |= SequenceNumber16Flag;
        }

        if (lengthPresent)
        {
            first |= LengthFlag;
        }

        first |= (byte)(epochLowBits & EpochMask);

        int offset = 0;
        destination[offset] = first;
        offset++;

        if (!connectionId.IsEmpty)
        {
            connectionId.CopyTo(destination.Slice(offset));
            offset += connectionId.Length;
        }

        if (sixteenBitSequenceNumber)
        {
            BinaryPrimitives.WriteUInt16BigEndian(destination.Slice(offset), sequenceNumber);
            offset += 2;
        }
        else
        {
            destination[offset] = (byte)sequenceNumber;
            offset++;
        }

        if (lengthPresent)
        {
            BinaryPrimitives.WriteUInt16BigEndian(destination.Slice(offset), length);
            offset += 2;
        }

        return offset;
    }

    /// <summary>
    /// Parses a unified record header from <paramref name="record"/>.
    /// </summary>
    /// <param name="record">The record bytes, header first.</param>
    /// <param name="connectionIdLength">
    /// The Connection ID length negotiated for this association (0 when none is used). It
    /// is only consumed when the header's Connection ID flag is set.
    /// </param>
    /// <param name="info">The parsed header fields on success.</param>
    /// <returns><see langword="true"/> when the header is well formed.</returns>
    public static bool TryParse(
        ReadOnlySpan<byte> record,
        int connectionIdLength,
        out Dtls13RecordHeaderInfo info)
    {
        info = default;

        if (record.IsEmpty)
        {
            return false;
        }

        byte first = record[0];
        if ((first & FixedBitsMask) != FixedBits)
        {
            return false;
        }

        bool cidPresent = (first & ConnectionIdFlag) != 0;
        bool sixteenBit = (first & SequenceNumber16Flag) != 0;
        bool lengthPresent = (first & LengthFlag) != 0;
        int epochLowBits = first & EpochMask;

        int offset = 1;
        int cidLength = 0;
        int cidOffset = offset;
        if (cidPresent)
        {
            if (connectionIdLength < 0)
            {
                return false;
            }

            cidLength = connectionIdLength;
            if (record.Length < offset + cidLength)
            {
                return false;
            }

            offset += cidLength;
        }

        int seqLength = sixteenBit ? 2 : 1;
        int seqOffset = offset;
        if (record.Length < offset + seqLength)
        {
            return false;
        }

        ushort encodedSeq = sixteenBit
            ? BinaryPrimitives.ReadUInt16BigEndian(record.Slice(offset, 2))
            : record[offset];
        offset += seqLength;

        int encryptedLength;
        if (lengthPresent)
        {
            if (record.Length < offset + 2)
            {
                return false;
            }

            ushort declared = BinaryPrimitives.ReadUInt16BigEndian(record.Slice(offset, 2));
            offset += 2;

            if (record.Length < offset + declared)
            {
                return false;
            }

            encryptedLength = declared;
        }
        else
        {
            encryptedLength = record.Length - offset;
        }

        info = new Dtls13RecordHeaderInfo
        {
            FirstByte = first,
            EpochLowBits = epochLowBits,
            ConnectionIdPresent = cidPresent,
            ConnectionIdOffset = cidOffset,
            ConnectionIdLength = cidLength,
            SixteenBitSequenceNumber = sixteenBit,
            SequenceNumberOffset = seqOffset,
            SequenceNumberLength = seqLength,
            EncodedSequenceNumber = encodedSeq,
            LengthPresent = lengthPresent,
            HeaderLength = offset,
            EncryptedRecordOffset = offset,
            EncryptedRecordLength = encryptedLength,
        };

        return true;
    }
}
