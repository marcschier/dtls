using System;
using System.Collections.Generic;
using System.Threading;
using System.Threading.Tasks;

namespace Dtls.Protocol.V13.Handshake;

/// <summary>
/// One handshake message queued for an outbound flight: its type, sequence number, and body.
/// </summary>
internal readonly struct OutboundHandshakeMessage
{
    public OutboundHandshakeMessage(HandshakeType type, ushort messageSequence, byte[] body)
    {
        Type = type;
        MessageSequence = messageSequence;
        Body = body;
    }

    public HandshakeType Type { get; }

    public ushort MessageSequence { get; }

    public byte[] Body { get; }
}

/// <summary>
/// Builds and receives DTLS 1.3 handshake flights with message fragmentation/reassembly
/// (RFC 9147 section 5.5). Outbound messages larger than the transport MTU are split into
/// fragment records packed into datagrams; inbound fragments are reassembled (via
/// <see cref="HandshakeReassembler"/>) into complete messages before the driver parses them.
/// </summary>
internal static class Dtls13HandshakeFlight
{
    /// <summary>
    /// The largest fragment body that fits one protected epoch-2 record within
    /// <paramref name="maxDatagramSize"/>. Computed conservatively (assuming a two-byte record
    /// sequence number) so no record exceeds the MTU regardless of its sequence number.
    /// </summary>
    public static int MaxProtectedFragmentBody(
        Dtls13RecordProtector protector,
        int maxDatagramSize)
    {
        int recordOverhead = protector.GetSealedLength(0, 256, HandshakeMessage.HeaderLength);
        return Math.Max(1, maxDatagramSize - recordOverhead);
    }

    /// <summary>
    /// The largest fragment body that fits one plaintext epoch-0 record within
    /// <paramref name="maxDatagramSize"/>.
    /// </summary>
    public static int MaxPlaintextFragmentBody(int maxDatagramSize)
    {
        return Math.Max(
            1,
            maxDatagramSize - Dtls13PlaintextRecord.HeaderLength - HandshakeMessage.HeaderLength);
    }

    /// <summary>
    /// Builds a protected (epoch-2) flight: fragments each message to the MTU, seals each fragment
    /// as a record (record sequence numbers increasing from
    /// <paramref name="startRecordSequence"/>), and packs the records into datagrams no larger than
    /// <paramref name="maxDatagramSize"/>.
    /// Returns the datagrams and the next unused record sequence number.
    /// </summary>
    public static (List<byte[]> Datagrams, ulong NextRecordSequence) BuildProtected(
        IReadOnlyList<OutboundHandshakeMessage> messages,
        Dtls13RecordProtector protector,
        int maxDatagramSize,
        ulong startRecordSequence)
    {
        int maxFragmentBody = MaxProtectedFragmentBody(protector, maxDatagramSize);
        return Build(
            messages,
            maxFragmentBody,
            maxDatagramSize,
            startRecordSequence,
            (sequence, fragment) =>
                Dtls13HandshakeRecords.SealHandshakeRecord(protector, sequence, fragment));
    }

    /// <summary>
    /// Builds a plaintext (epoch-0) flight (ClientHello/ServerHello/HelloRetryRequest), fragmenting
    /// to the MTU and packing into datagrams. Returns the datagrams and the next record sequence.
    /// </summary>
    public static (List<byte[]> Datagrams, ulong NextRecordSequence) BuildPlaintext(
        IReadOnlyList<OutboundHandshakeMessage> messages,
        int maxDatagramSize,
        ulong startRecordSequence)
    {
        int maxFragmentBody = MaxPlaintextFragmentBody(maxDatagramSize);
        return Build(
            messages,
            maxFragmentBody,
            maxDatagramSize,
            startRecordSequence,
            (sequence, fragment) => Dtls13PlaintextRecord.Encode(
                Dtls13PlaintextRecord.HandshakeContentType, 0, sequence, fragment));
    }

    /// <summary>
    /// Sends one plaintext (epoch-0) hello through <paramref name="transceiver"/>, fragmenting it
    /// to the transport MTU across datagrams if necessary.
    /// </summary>
    public static async Task SendPlaintextAsync(
        Dtls13FlightTransceiver transceiver,
        HandshakeType type,
        ushort messageSequence,
        byte[] body,
        ulong recordSequence,
        CancellationToken cancellationToken)
    {
        (List<byte[]> datagrams, _) = BuildPlaintext(
            new[] { new OutboundHandshakeMessage(type, messageSequence, body) },
            transceiver.Transport.MaxDatagramSize,
            recordSequence);
        foreach (byte[] datagram in datagrams)
        {
            await transceiver.SendAsync(datagram, cancellationToken).ConfigureAwait(false);
        }
    }

    private static (List<byte[]>, ulong) Build(
        IReadOnlyList<OutboundHandshakeMessage> messages,
        int maxFragmentBody,
        int maxDatagramSize,
        ulong startRecordSequence,
        Func<ulong, byte[], byte[]> seal)
    {
        List<byte[]> records = new();
        ulong recordSequence = startRecordSequence;
        foreach (OutboundHandshakeMessage message in messages)
        {
            List<byte[]> fragments = HandshakeReassembler.Fragment(
                message.Type, message.MessageSequence, message.Body, maxFragmentBody);
            foreach (byte[] fragment in fragments)
            {
                records.Add(seal(recordSequence, fragment));
                recordSequence++;
            }
        }

        return (Pack(records, maxDatagramSize), recordSequence);
    }

    private static List<byte[]> Pack(List<byte[]> records, int maxDatagramSize)
    {
        List<byte[]> datagrams = new();
        int index = 0;
        while (index < records.Count)
        {
            int length = 0;
            int start = index;
            while (index < records.Count
                && (length == 0 || length + records[index].Length <= maxDatagramSize))
            {
                length += records[index].Length;
                index++;
            }

            byte[] datagram = new byte[length];
            int offset = 0;
            for (int j = start; j < index; j++)
            {
                records[j].CopyTo(datagram, offset);
                offset += records[j].Length;
            }

            datagrams.Add(datagram);
        }

        return datagrams;
    }

    /// <summary>
    /// Receives and reassembles a protected (epoch-2) flight, retransmitting on loss via
    /// <paramref name="transceiver"/>, until a message of type <paramref name="terminator"/> (the
    /// flight's last message, normally Finished) is reassembled. Returns the reassembled messages
    /// in sequence order.
    /// </summary>
    public static async Task<List<Dtls13HandshakeRecords.Message>> ReceiveProtectedAsync(
        Dtls13FlightTransceiver transceiver,
        HandshakeReassembler reassembler,
        Dtls13RecordProtector protector,
        HandshakeType terminator,
        CancellationToken cancellationToken)
    {
        List<Dtls13HandshakeRecords.Message> messages = new();
        while (true)
        {
            byte[] datagram = await transceiver.ReceiveFlightAsync(cancellationToken)
                .ConfigureAwait(false);
            OfferProtected(datagram, protector, reassembler);

            while (reassembler.TryReadNext(
                out HandshakeType type, out byte[] body, out ushort sequence))
            {
                messages.Add(new Dtls13HandshakeRecords.Message(type, body, sequence));
                if (type == terminator)
                {
                    return messages;
                }
            }
        }
    }

    /// <summary>
    /// Receives and reassembles a single plaintext (epoch-0) handshake message — a hello
    /// (ClientHello/ServerHello/HelloRetryRequest) — retransmitting on loss via
    /// <paramref name="transceiver"/>. Datagrams that carry no plaintext handshake fragment (for
    /// example a protected flight that arrives early) are forgotten so the transceiver redelivers
    /// them to a later receive. Returns the reassembled message type and body.
    /// </summary>
    public static async Task<(HandshakeType Type, byte[] Body)> ReceivePlaintextHandshakeAsync(
        Dtls13FlightTransceiver transceiver,
        ushort firstSequence,
        int maxMessageLength,
        CancellationToken cancellationToken)
    {
        HandshakeReassembler reassembler = new(maxMessageLength, firstSequence);
        while (true)
        {
            byte[] datagram = await transceiver.ReceiveFlightAsync(cancellationToken)
                .ConfigureAwait(false);
            bool offered = OfferPlaintext(datagram, reassembler);

            if (reassembler.TryReadNext(out HandshakeType type, out byte[] body, out _))
            {
                return (type, body);
            }

            if (!offered)
            {
                transceiver.Forget(datagram);
            }
        }
    }

    /// <summary>
    /// Offers every plaintext (epoch-0) handshake fragment in <paramref name="datagram"/> to
    /// <paramref name="reassembler"/>. Returns whether at least one plaintext handshake record was
    /// found (so the caller can forget datagrams that carry none, such as protected flights).
    /// </summary>
    public static bool OfferPlaintext(
        ReadOnlySpan<byte> datagram,
        HandshakeReassembler reassembler)
    {
        bool foundHandshake = false;
        ReadOnlySpan<byte> remaining = datagram;
        while (Dtls13PlaintextRecord.TryParse(
            remaining,
            out byte contentType,
            out _,
            out _,
            out ReadOnlySpan<byte> fragment,
            out int consumed))
        {
            remaining = remaining.Slice(consumed);
            if (contentType == Dtls13PlaintextRecord.HandshakeContentType)
            {
                foundHandshake = true;
                OfferFragment(fragment, reassembler);
            }
        }

        return foundHandshake;
    }

    private static void OfferProtected(
        ReadOnlySpan<byte> datagram,
        Dtls13RecordProtector protector,
        HandshakeReassembler reassembler)
    {
        ReadOnlySpan<byte> remaining = datagram;
        while (!remaining.IsEmpty)
        {
            if (!Dtls13RecordHeader.TryParse(remaining, 0, out var header))
            {
                break;
            }

            int recordLength = header.HeaderLength + header.EncryptedRecordLength;
            if (recordLength <= 0 || recordLength > remaining.Length)
            {
                break;
            }

            ReadOnlySpan<byte> record = remaining.Slice(0, recordLength);
            remaining = remaining.Slice(recordLength);

            if (!protector.TryOpen(record, out byte contentType, out byte[] plaintext, out _))
            {
                continue;
            }

            try
            {
                if (contentType == Dtls13PlaintextRecord.HandshakeContentType)
                {
                    OfferFragment(plaintext, reassembler);
                }
            }
            finally
            {
                Array.Clear(plaintext, 0, plaintext.Length);
            }
        }
    }

    /// <summary>
    /// Offers every handshake fragment carried in <paramref name="plaintext"/> (one or more
    /// concatenated handshake fragments) to <paramref name="reassembler"/>.
    /// </summary>
    public static void OfferFragment(
        ReadOnlySpan<byte> plaintext,
        HandshakeReassembler reassembler)
    {
        ReadOnlySpan<byte> remaining = plaintext;
        while (HandshakeMessage.TryParseHeader(remaining, out HandshakeMessageHeader header))
        {
            int fragmentLength = header.FragmentLength;
            if (fragmentLength < 0
                || remaining.Length < HandshakeMessage.HeaderLength + fragmentLength)
            {
                break;
            }

            reassembler.Offer(
                header, remaining.Slice(HandshakeMessage.HeaderLength, fragmentLength));
            remaining = remaining.Slice(HandshakeMessage.HeaderLength + fragmentLength);
        }
    }
}
