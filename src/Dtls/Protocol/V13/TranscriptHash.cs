using System;
using System.Security.Cryptography;
using Dtls.Crypto;
using Dtls.Internal;
using Dtls.Protocol.V13.Handshake;

namespace Dtls.Protocol.V13;

/// <summary>
/// An incremental TLS 1.3 / DTLS 1.3 transcript hash (RFC 8446 section 4.4.1, RFC 9147
/// section 5.2). Messages are accumulated in their TLS 1.3 reconstructed form
/// (<c>msg_type || length(uint24) || body</c>, without the DTLS message_seq/fragment
/// fields). The running hash value can be snapshotted at any point, the transcript can be
/// cloned, and a partial (binder) transcript can be computed by hashing the accumulated
/// bytes followed by a not-yet-committed suffix.
/// </summary>
internal sealed class TranscriptHash
{
    private readonly HashAlgorithmName _hash;
    private byte[] _buffer;
    private int _length;

    public TranscriptHash(HashAlgorithmName hash)
    {
        _hash = hash;
        _buffer = new byte[128];
        _length = 0;
    }

    private TranscriptHash(HashAlgorithmName hash, byte[] buffer, int length)
    {
        _hash = hash;
        _buffer = buffer;
        _length = length;
    }

    /// <summary>The hash algorithm driving this transcript.</summary>
    public HashAlgorithmName Hash => _hash;

    /// <summary>The output length, in bytes, of the transcript hash.</summary>
    public int HashLength => Hkdf.HashLength(_hash);

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

    /// <summary>
    /// Appends already-reconstructed handshake bytes (<c>msg_type || length || body</c>) to
    /// the transcript.
    /// </summary>
    public void AppendRaw(ReadOnlySpan<byte> reconstructedMessage)
    {
        EnsureCapacity(reconstructedMessage.Length);
        reconstructedMessage.CopyTo(_buffer.AsSpan(_length));
        _length += reconstructedMessage.Length;
    }

    /// <summary>
    /// Appends a handshake message to the transcript by reconstructing its TLS 1.3 form
    /// from <paramref name="messageType"/> and <paramref name="body"/>.
    /// </summary>
    public void AppendMessage(HandshakeType messageType, ReadOnlySpan<byte> body)
    {
        if (body.Length > 0xFFFFFF)
        {
            throw new ArgumentOutOfRangeException(nameof(body));
        }

        EnsureCapacity(4 + body.Length);
        Span<byte> destination = _buffer.AsSpan(_length);
        destination[0] = (byte)messageType;
        BinaryHelpers.WriteUInt24BigEndian(destination.Slice(1, 3), (uint)body.Length);
        body.CopyTo(destination.Slice(4));
        _length += 4 + body.Length;
    }

    /// <summary>Computes the current transcript hash over all accumulated bytes.</summary>
    public byte[] CurrentHash()
    {
        using IncrementalHash digest = IncrementalHash.CreateHash(_hash);
        digest.AppendData(_buffer, 0, _length);
        return digest.GetHashAndReset();
    }

    /// <summary>
    /// Computes a transcript hash over the accumulated bytes followed by
    /// <paramref name="suffix"/> without committing the suffix. This is the binder
    /// transcript (RFC 8446 section 4.2.11.2): the accumulated transcript plus the
    /// truncated ClientHello.
    /// </summary>
    public byte[] HashWithSuffix(ReadOnlySpan<byte> suffix)
    {
        using IncrementalHash digest = IncrementalHash.CreateHash(_hash);
        digest.AppendData(_buffer, 0, _length);
        if (!suffix.IsEmpty)
        {
            digest.AppendData(suffix.ToArray());
        }

        return digest.GetHashAndReset();
    }

    /// <summary>Creates an independent copy of this transcript at its current state.</summary>
    public TranscriptHash Clone()
    {
        byte[] copy = new byte[_buffer.Length];
        Array.Copy(_buffer, copy, _length);
        return new TranscriptHash(_hash, copy, _length);
    }

    /// <summary>
    /// Reconstructs the synthetic <c>message_hash</c> handshake message used after a
    /// HelloRetryRequest (RFC 8446 section 4.4.1):
    /// <c>message_hash(254) || 00 00 Hash.length || Hash(ClientHello1)</c>.
    /// </summary>
    public static byte[] SynthesizeMessageHash(
        HashAlgorithmName hash,
        ReadOnlySpan<byte> clientHello1)
    {
        int hashLength = Hkdf.HashLength(hash);
        byte[] clientHelloHash;
        using (IncrementalHash digest = IncrementalHash.CreateHash(hash))
        {
            digest.AppendData(clientHello1.ToArray());
            clientHelloHash = digest.GetHashAndReset();
        }

        return HandshakeMessage.ToTranscriptBytes(HandshakeType.MessageHash, clientHelloHash);
    }
}
