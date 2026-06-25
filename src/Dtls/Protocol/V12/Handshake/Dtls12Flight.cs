using System;
using System.Collections.Generic;
using System.Threading;
using System.Threading.Tasks;
using Dtls.Protocol.V13;
using Dtls.Protocol.V13.Handshake;

namespace Dtls.Protocol.V12.Handshake;

/// <summary>
/// Send/receive helpers for the DTLS 1.2 handshake flights, layered on the shared
/// <see cref="Dtls13FlightTransceiver"/> (retransmission, RFC 9147 section 5.8) and the shared
/// DTLSPlaintext codec and handshake fragmentation/reassembly. DTLS 1.2 differs from 1.3 in that
/// the ClientHello..ServerHelloDone and ClientKeyExchange flights are epoch-0 plaintext, a
/// ChangeCipherSpec record (content type 20) precedes the Finished, and the Finished is an epoch-1
/// AEAD-protected record. There are no ACKs (RFC 6347 uses pure timeout retransmission).
/// </summary>
internal static class Dtls12Flight
{
    /// <summary>The ChangeCipherSpec record content type (RFC 5246 section 7.1).</summary>
    public const byte ChangeCipherSpecContentType = 20;

    /// <summary>The first protected (epoch-1) record sequence number for the Finished.</summary>
    public const ulong FinishedSequenceNumber = 0;

    /// <summary>
    /// Sends a plaintext (epoch-0) flight of one or more handshake messages, fragmenting each to
    /// the transport MTU and packing the resulting records into datagrams. Returns the next unused
    /// epoch-0 record sequence number.
    /// </summary>
    public static async Task<ulong> SendPlaintextFlightAsync(
        Dtls13FlightTransceiver transceiver,
        IReadOnlyList<OutboundHandshakeMessage> messages,
        ulong recordSequence,
        CancellationToken cancellationToken)
    {
        (List<byte[]> datagrams, ulong next) = Dtls13HandshakeFlight.BuildPlaintext(
            messages, transceiver.Transport.MaxDatagramSize, recordSequence);
        foreach (byte[] datagram in datagrams)
        {
            await transceiver.SendAsync(datagram, cancellationToken).ConfigureAwait(false);
        }

        return next;
    }

    /// <summary>
    /// Receives and reassembles a plaintext (epoch-0) flight, retransmitting the current outbound
    /// flight on loss, until a message of type <paramref name="terminator"/> is reassembled.
    /// Returns the reassembled messages in sequence order.
    /// </summary>
    public static async Task<List<Dtls13HandshakeRecords.Message>> ReceivePlaintextFlightAsync(
        Dtls13FlightTransceiver transceiver,
        HandshakeReassembler reassembler,
        HandshakeType terminator,
        CancellationToken cancellationToken)
    {
        List<Dtls13HandshakeRecords.Message> messages = new();
        while (true)
        {
            byte[] datagram = await transceiver.ReceiveFlightAsync(cancellationToken)
                .ConfigureAwait(false);
            Dtls13HandshakeFlight.OfferPlaintext(datagram, reassembler);

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
    /// Builds the final flight datagrams: the supplied epoch-0 plaintext handshake messages
    /// (for example ClientKeyExchange, optionally Certificate/CertificateVerify), then a
    /// ChangeCipherSpec record, then the epoch-1 AEAD-protected Finished. Records are packed into
    /// datagrams no larger than <paramref name="maxDatagramSize"/>.
    /// </summary>
    public static List<byte[]> BuildFinalFlight(
        IReadOnlyList<OutboundHandshakeMessage> plaintextMessages,
        ulong recordSequence,
        Dtls12RecordProtector sendProtector,
        byte[] finishedMessage,
        int maxDatagramSize)
    {
        List<byte[]> records = new();
        ulong sequence = recordSequence;

        int maxFragmentBody = Math.Max(
            1,
            maxDatagramSize - Dtls13PlaintextRecord.HeaderLength - HandshakeMessage.HeaderLength);
        foreach (OutboundHandshakeMessage message in plaintextMessages)
        {
            List<byte[]> fragments = HandshakeReassembler.Fragment(
                message.Type, message.MessageSequence, message.Body, maxFragmentBody);
            foreach (byte[] fragment in fragments)
            {
                records.Add(Dtls13PlaintextRecord.Encode(
                    Dtls13PlaintextRecord.HandshakeContentType, 0, sequence, fragment));
                sequence++;
            }
        }

        records.Add(Dtls13PlaintextRecord.Encode(
            ChangeCipherSpecContentType, 0, sequence, stackalloc byte[] { 0x01 }));

        byte[] finishedRecord = new byte[sendProtector.GetSealedLength(finishedMessage.Length)];
        sendProtector.Seal(
            1,
            FinishedSequenceNumber,
            Dtls13PlaintextRecord.HandshakeContentType,
            finishedMessage,
            finishedRecord);
        records.Add(finishedRecord);

        return Pack(records, maxDatagramSize);
    }

    /// <summary>
    /// Sends each datagram of a prebuilt flight through <paramref name="transceiver"/>.
    /// </summary>
    public static async Task SendDatagramsAsync(
        Dtls13FlightTransceiver transceiver,
        IReadOnlyList<byte[]> datagrams,
        CancellationToken cancellationToken)
    {
        foreach (byte[] datagram in datagrams)
        {
            await transceiver.SendAsync(datagram, cancellationToken).ConfigureAwait(false);
        }
    }

    /// <summary>
    /// Receives the peer's final flight: any epoch-0 plaintext handshake messages (reassembled via
    /// <paramref name="plaintextReassembler"/>), a ChangeCipherSpec, and the epoch-1 protected
    /// Finished (opened with <paramref name="receiveProtector"/>). Returns the reassembled
    /// plaintext messages and the Finished body (verify_data). Retransmits the flight on loss.
    /// </summary>
    public static async Task<(List<Dtls13HandshakeRecords.Message> Plaintext, byte[] FinishedBody)>
        ReceiveFinalFlightAsync(
            Dtls13FlightTransceiver transceiver,
            HandshakeReassembler plaintextReassembler,
            Dtls12RecordProtector receiveProtector,
            CancellationToken cancellationToken)
    {
        List<Dtls13HandshakeRecords.Message> plaintext = new();
        while (true)
        {
            byte[] datagram = await transceiver.ReceiveFlightAsync(cancellationToken)
                .ConfigureAwait(false);

            ReadOnlySpan<byte> remaining = datagram;
            while (Dtls13PlaintextRecord.TryParse(
                remaining,
                out byte contentType,
                out ushort epoch,
                out _,
                out ReadOnlySpan<byte> fragment,
                out int consumed))
            {
                ReadOnlySpan<byte> record = remaining.Slice(0, consumed);
                remaining = remaining.Slice(consumed);

                if (epoch == 0 && contentType == Dtls13PlaintextRecord.HandshakeContentType)
                {
                    Dtls13HandshakeFlight.OfferFragment(fragment, plaintextReassembler);
                    while (plaintextReassembler.TryReadNext(
                        out HandshakeType type, out byte[] body, out ushort sequence))
                    {
                        plaintext.Add(new Dtls13HandshakeRecords.Message(type, body, sequence));
                    }
                }
                else if (epoch >= 1
                    && contentType == Dtls13PlaintextRecord.HandshakeContentType)
                {
                    if (receiveProtector.TryOpen(
                        record, out byte openedType, out byte[] opened, out _, out _, out _)
                        && openedType == Dtls13PlaintextRecord.HandshakeContentType
                        && HandshakeMessage.TryParse(
                            opened, out HandshakeMessageHeader header, out ReadOnlySpan<byte> body)
                        && header.MessageType == HandshakeType.Finished)
                    {
                        return (plaintext, body.ToArray());
                    }
                }
            }
        }
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
}
