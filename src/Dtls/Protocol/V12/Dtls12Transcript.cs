using System;
using System.Security.Cryptography;
using Dtls.Protocol.V13.Handshake;

namespace Dtls.Protocol.V12;

/// <summary>
/// An incremental DTLS 1.2 handshake transcript (RFC 6347 section 4.2.6, RFC 5246 section 7.4.9).
/// Unlike DTLS 1.3, the transcript hashes each handshake message in its full DTLS form including
/// the 12-byte handshake header (<c>msg_type || length || message_seq || fragment_offset=0 ||
/// fragment_length=length</c>), reassembled as a single fragment. The initial cookieless
/// ClientHello and the HelloVerifyRequest are excluded by the drivers (they simply are not
/// appended). The running hash backs the extended_master_secret session_hash, the Finished
/// verify_data, and the CertificateVerify signed content.
/// </summary>
internal sealed class Dtls12Transcript
{
    private readonly HashAlgorithmName _hash;
    private byte[] _buffer;
    private int _length;

    public Dtls12Transcript(HashAlgorithmName hash)
    {
        _hash = hash;
        _buffer = new byte[256];
        _length = 0;
    }

    /// <summary>
    /// Appends a complete handshake message (reconstructed as a single fragment) to the transcript.
    /// </summary>
    public void Append(HandshakeType type, ushort messageSequence, ReadOnlySpan<byte> body)
    {
        byte[] message = HandshakeMessage.Serialize(type, messageSequence, body);
        EnsureCapacity(message.Length);
        message.CopyTo(_buffer.AsSpan(_length));
        _length += message.Length;
    }

    /// <summary>Computes the hash over all accumulated handshake messages.</summary>
    public byte[] CurrentHash()
    {
        using IncrementalHash digest = IncrementalHash.CreateHash(_hash);
        digest.AppendData(_buffer, 0, _length);
        return digest.GetHashAndReset();
    }

    /// <summary>
    /// Returns a copy of all accumulated handshake-message bytes. CertificateVerify (RFC 5246
    /// section 7.4.8) signs these raw bytes (the signing primitive hashes them internally).
    /// </summary>
    public byte[] CurrentBytes()
    {
        byte[] copy = new byte[_length];
        Array.Copy(_buffer, copy, _length);
        return copy;
    }

    private void EnsureCapacity(int additional)
    {
        int required = _length + additional;
        if (required <= _buffer.Length)
        {
            return;
        }

        int newCapacity = _buffer.Length * 2;
        while (newCapacity < required)
        {
            newCapacity *= 2;
        }

        Array.Resize(ref _buffer, newCapacity);
    }
}
