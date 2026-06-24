using System;
using System.Buffers.Binary;
using System.Collections.Generic;

namespace Dtls.Protocol.V13;

/// <summary>
/// A DTLS 1.3 record number: the (epoch, sequence_number) pair that uniquely identifies a record
/// within a connection (RFC 9147 section 4 / section 7). Used to track which handshake records
/// have been sent (for retransmission) and acknowledged (for ACK processing).
/// </summary>
internal readonly struct RecordNumber : IEquatable<RecordNumber>
{
    public RecordNumber(ulong epoch, ulong sequenceNumber)
    {
        Epoch = epoch;
        SequenceNumber = sequenceNumber;
    }

    /// <summary>The record epoch.</summary>
    public ulong Epoch { get; }

    /// <summary>The 48-bit record sequence number (carried as a 64-bit value in ACKs).</summary>
    public ulong SequenceNumber { get; }

    public bool Equals(RecordNumber other) =>
        Epoch == other.Epoch && SequenceNumber == other.SequenceNumber;

    public override bool Equals(object? obj) => obj is RecordNumber other && Equals(other);

    public override int GetHashCode() => HashCode.Combine(Epoch, SequenceNumber);
}

/// <summary>
/// Encoder/decoder for the DTLS 1.3 ACK message body (RFC 9147 section 7):
/// <c>struct { RecordNumber record_numbers&lt;0..2^16-1&gt;; } ACK;</c> where each
/// <c>RecordNumber</c> is <c>uint64 epoch || uint64 sequence_number</c> (16 bytes). The ACK body
/// is carried in a record with the <see cref="Dtls13PlaintextRecord.AckContentType"/> content type.
/// </summary>
internal static class Dtls13Ack
{
    private const int RecordNumberSize = 16;

    /// <summary>Encodes an ACK body listing <paramref name="recordNumbers"/>.</summary>
    public static byte[] Encode(IReadOnlyList<RecordNumber> recordNumbers)
    {
        if (recordNumbers is null)
        {
            throw new ArgumentNullException(nameof(recordNumbers));
        }

        int listBytes = recordNumbers.Count * RecordNumberSize;
        if (listBytes > ushort.MaxValue)
        {
            throw new ArgumentException(
                "Too many record numbers for one ACK.", nameof(recordNumbers));
        }

        byte[] body = new byte[2 + listBytes];
        Span<byte> span = body;
        BinaryPrimitives.WriteUInt16BigEndian(span.Slice(0, 2), (ushort)listBytes);
        int offset = 2;
        for (int i = 0; i < recordNumbers.Count; i++)
        {
            BinaryPrimitives.WriteUInt64BigEndian(span.Slice(offset, 8), recordNumbers[i].Epoch);
            BinaryPrimitives.WriteUInt64BigEndian(
                span.Slice(offset + 8, 8), recordNumbers[i].SequenceNumber);
            offset += RecordNumberSize;
        }

        return body;
    }

    /// <summary>Parses an ACK body into the acknowledged record numbers.</summary>
    public static bool TryParse(ReadOnlySpan<byte> body, out List<RecordNumber> recordNumbers)
    {
        recordNumbers = new List<RecordNumber>();
        if (body.Length < 2)
        {
            return false;
        }

        int listBytes = BinaryPrimitives.ReadUInt16BigEndian(body.Slice(0, 2));
        if (listBytes % RecordNumberSize != 0 || 2 + listBytes > body.Length)
        {
            return false;
        }

        int offset = 2;
        for (int i = 0; i < listBytes / RecordNumberSize; i++)
        {
            ulong epoch = BinaryPrimitives.ReadUInt64BigEndian(body.Slice(offset, 8));
            ulong seq = BinaryPrimitives.ReadUInt64BigEndian(body.Slice(offset + 8, 8));
            recordNumbers.Add(new RecordNumber(epoch, seq));
            offset += RecordNumberSize;
        }

        return true;
    }
}
