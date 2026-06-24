using System;
using System.Collections.Generic;
using Dtls.Internal;

namespace Dtls.Protocol.V13.Handshake;

/// <summary>
/// Fragments outbound DTLS 1.3 handshake messages to fit a transport MTU and reassembles inbound
/// fragments back into complete messages (RFC 9147 section 5.5). The DTLS handshake header carries
/// <c>message_seq</c>, <c>fragment_offset</c>, and <c>fragment_length</c>, allowing one logical
/// message to be split across records/datagrams and reassembled in order on the receiver.
/// </summary>
internal sealed class HandshakeReassembler
{
    private readonly int _maxMessageLength;
    private readonly Dictionary<ushort, MessageBuffer> _buffers = new();
    private ushort _nextSequence;

    /// <summary>Creates a reassembler bounding reassembled messages to a maximum size.</summary>
    /// <param name="maxMessageLength">
    /// The largest reassembled message accepted (bounds memory; mirrors
    /// <c>DtlsOptions.MaxHandshakeMessageSize</c>).
    /// </param>
    /// <param name="firstSequence">
    /// The <c>message_seq</c> of the first message expected by this reassembler. Messages are
    /// delivered in order starting from this value; fragments with a lower sequence are ignored.
    /// Defaults to 0 (the start of a handshake); set it to the first sequence of a mid-handshake
    /// flight so a per-flight reassembler delivers that flight's messages.
    /// </param>
    public HandshakeReassembler(int maxMessageLength, ushort firstSequence = 0)
    {
        _maxMessageLength = maxMessageLength;
        _nextSequence = firstSequence;
    }

    /// <summary>
    /// Splits a complete handshake message body into fragment records (each a full DTLS handshake
    /// header plus a slice of the body) no larger than <paramref name="maxFragmentBodyLength"/>.
    /// A single fragment is produced for messages that already fit.
    /// </summary>
    public static List<byte[]> Fragment(
        HandshakeType messageType,
        ushort messageSequence,
        ReadOnlySpan<byte> body,
        int maxFragmentBodyLength)
    {
        if (maxFragmentBodyLength < 1)
        {
            maxFragmentBodyLength = 1;
        }

        List<byte[]> fragments = new();
        int total = body.Length;
        int offset = 0;
        do
        {
            int fragmentLength = Math.Min(maxFragmentBodyLength, total - offset);
            TlsWriter writer = new(HandshakeMessage.HeaderLength + fragmentLength);
            HandshakeMessage.WriteHeader(
                writer, messageType, total, messageSequence, offset, fragmentLength);
            writer.WriteBytes(body.Slice(offset, fragmentLength));
            fragments.Add(writer.ToArray());
            offset += fragmentLength;
        }
        while (offset < total);

        return fragments;
    }

    /// <summary>
    /// Offers one parsed handshake fragment for reassembly. Fragments for already-delivered or
    /// malformed messages are ignored.
    /// </summary>
    public void Offer(in HandshakeMessageHeader header, ReadOnlySpan<byte> fragmentBytes)
    {
        if (header.MessageSequence < _nextSequence)
        {
            return;
        }

        if (header.Length < 0 || header.Length > _maxMessageLength)
        {
            return;
        }

        if (header.FragmentOffset < 0
            || header.FragmentLength < 0
            || header.FragmentOffset + header.FragmentLength > header.Length
            || fragmentBytes.Length < header.FragmentLength)
        {
            return;
        }

        if (!_buffers.TryGetValue(header.MessageSequence, out MessageBuffer? buffer))
        {
            buffer = new MessageBuffer(header.MessageType, header.Length);
            _buffers[header.MessageSequence] = buffer;
        }

        buffer.Receive(header.FragmentOffset, fragmentBytes.Slice(0, header.FragmentLength));
    }

    /// <summary>
    /// Returns the next in-order fully reassembled handshake message, if available, advancing the
    /// expected sequence number.
    /// </summary>
    public bool TryReadNext(out HandshakeType type, out byte[] body, out ushort sequence)
    {
        type = default;
        body = Array.Empty<byte>();
        sequence = _nextSequence;

        if (!_buffers.TryGetValue(_nextSequence, out MessageBuffer? buffer) || !buffer.IsComplete)
        {
            return false;
        }

        type = buffer.MessageType;
        body = buffer.Body;
        _buffers.Remove(_nextSequence);
        _nextSequence++;
        return true;
    }

    private sealed class MessageBuffer
    {
        private readonly byte[] _body;
        private readonly bool[] _received;
        private int _receivedCount;

        public MessageBuffer(HandshakeType messageType, int length)
        {
            MessageType = messageType;
            _body = new byte[length];
            _received = new bool[length];
        }

        public HandshakeType MessageType { get; }

        public bool IsComplete => _receivedCount == _body.Length;

        public byte[] Body => _body;

        public void Receive(int offset, ReadOnlySpan<byte> data)
        {
            data.CopyTo(_body.AsSpan(offset));
            for (int i = 0; i < data.Length; i++)
            {
                if (!_received[offset + i])
                {
                    _received[offset + i] = true;
                    _receivedCount++;
                }
            }
        }
    }
}
