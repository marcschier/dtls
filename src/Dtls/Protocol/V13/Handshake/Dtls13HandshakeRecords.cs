using System;
using System.Collections.Generic;
using Dtls.Crypto;

namespace Dtls.Protocol.V13.Handshake;

/// <summary>
/// Shared record-level helpers for the managed DTLS 1.3 handshake drivers: reading the
/// epoch-0 plaintext hello records and the protected epoch-2 handshake flights, and
/// building record protectors from a traffic secret.
/// </summary>
internal static class Dtls13HandshakeRecords
{
    /// <summary>A handshake message recovered from a flight: its type and TLS body.</summary>
    public readonly struct Message
    {
        public Message(HandshakeType type, byte[] body, ushort messageSequence)
        {
            Type = type;
            Body = body;
            MessageSequence = messageSequence;
        }

        public HandshakeType Type { get; }

        public byte[] Body { get; }

        public ushort MessageSequence { get; }
    }

    /// <summary>
    /// Builds a record protector for the supplied traffic secret and cipher suite.
    /// </summary>
    public static Dtls13RecordProtector CreateProtector(
        Dtls13CipherSuite suite,
        ReadOnlySpan<byte> trafficSecret)
    {
        return new Dtls13RecordProtector(Dtls13RecordKeys.Derive(suite, trafficSecret));
    }

    /// <summary>
    /// Seals one handshake message into a protected epoch-2 record.
    /// </summary>
    public static byte[] SealHandshakeRecord(
        Dtls13RecordProtector protector,
        ulong sequenceNumber,
        ReadOnlySpan<byte> handshakeMessage)
    {
        const ushort handshakeEpoch = 2;
        int sealedLength = protector.GetSealedLength(0, sequenceNumber, handshakeMessage.Length);
        byte[] record = new byte[sealedLength];
        protector.Seal(
            handshakeEpoch,
            sequenceNumber,
            Dtls13PlaintextRecord.HandshakeContentType,
            handshakeMessage,
            ReadOnlySpan<byte>.Empty,
            record);
        return record;
    }

    /// <summary>
    /// Reads the first epoch-0 plaintext handshake message from <paramref name="datagram"/>
    /// and returns its type and body.
    /// </summary>
    public static bool TryReadPlaintextHandshake(
        ReadOnlySpan<byte> datagram,
        out HandshakeType type,
        out byte[] body)
    {
        type = default;
        body = Array.Empty<byte>();

        if (!Dtls13PlaintextRecord.TryParse(
                datagram,
                out byte contentType,
                out _,
                out _,
                out ReadOnlySpan<byte> fragment,
                out _))
        {
            return false;
        }

        if (contentType != Dtls13PlaintextRecord.HandshakeContentType)
        {
            return false;
        }

        if (!HandshakeMessage.TryParse(
                fragment, out HandshakeMessageHeader header, out var msgBody))
        {
            return false;
        }

        type = header.MessageType;
        body = msgBody.ToArray();
        return true;
    }

    /// <summary>
    /// Opens every protected record in <paramref name="datagram"/> with
    /// <paramref name="protector"/> and returns the handshake messages they carry, in order.
    /// </summary>
    public static List<Message> OpenHandshakeFlight(
        ReadOnlySpan<byte> datagram,
        Dtls13RecordProtector protector)
    {
        List<Message> messages = new();
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

            if (contentType != Dtls13PlaintextRecord.HandshakeContentType)
            {
                continue;
            }

            if (HandshakeMessage.TryParse(
                    plaintext,
                    out HandshakeMessageHeader hsHeader,
                    out ReadOnlySpan<byte> body))
            {
                messages.Add(
                    new Message(hsHeader.MessageType, body.ToArray(), hsHeader.MessageSequence));
            }
        }

        return messages;
    }
}
