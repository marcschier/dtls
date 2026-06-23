using System;
using System.Buffers.Binary;

namespace Dtls.Internal;

/// <summary>
/// A growable, big-endian (network order) byte writer for assembling TLS 1.3 / DTLS 1.3
/// wire structures. It supports the nested length-prefixed vectors used throughout the
/// handshake: a vector is opened with one of the <c>BeginVectorN</c> methods, its content
/// is written, and the corresponding <c>EndVector</c> backfills the reserved length.
/// </summary>
internal sealed class TlsWriter
{
    private byte[] _buffer;
    private int _length;

    public TlsWriter(int initialCapacity = 64)
    {
        if (initialCapacity < 1)
        {
            initialCapacity = 1;
        }

        _buffer = new byte[initialCapacity];
        _length = 0;
    }

    /// <summary>The number of bytes written so far.</summary>
    public int Length => _length;

    /// <summary>A read-only view over the bytes written so far.</summary>
    public ReadOnlySpan<byte> WrittenSpan => _buffer.AsSpan(0, _length);

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

    public void WriteByte(byte value)
    {
        EnsureCapacity(1);
        _buffer[_length] = value;
        _length++;
    }

    public void WriteUInt16(ushort value)
    {
        EnsureCapacity(2);
        BinaryPrimitives.WriteUInt16BigEndian(_buffer.AsSpan(_length, 2), value);
        _length += 2;
    }

    public void WriteUInt24(uint value)
    {
        if (value > 0xFFFFFF)
        {
            throw new ArgumentOutOfRangeException(nameof(value), "Value exceeds 24 bits.");
        }

        EnsureCapacity(3);
        BinaryHelpers.WriteUInt24BigEndian(_buffer.AsSpan(_length, 3), value);
        _length += 3;
    }

    public void WriteUInt32(uint value)
    {
        EnsureCapacity(4);
        BinaryPrimitives.WriteUInt32BigEndian(_buffer.AsSpan(_length, 4), value);
        _length += 4;
    }

    public void WriteBytes(ReadOnlySpan<byte> bytes)
    {
        EnsureCapacity(bytes.Length);
        bytes.CopyTo(_buffer.AsSpan(_length));
        _length += bytes.Length;
    }

    /// <summary>Reserves an 8-bit length prefix and returns the content start offset.</summary>
    public int BeginVector8()
    {
        WriteByte(0);
        return _length;
    }

    /// <summary>Backfills the 8-bit length prefix opened by <see cref="BeginVector8"/>.</summary>
    public void EndVector8(int contentStart)
    {
        int contentLength = _length - contentStart;
        if (contentLength > 0xFF)
        {
            throw new InvalidOperationException("Vector length exceeds 8-bit prefix.");
        }

        _buffer[contentStart - 1] = (byte)contentLength;
    }

    /// <summary>Reserves a 16-bit length prefix and returns the content start offset.</summary>
    public int BeginVector16()
    {
        WriteUInt16(0);
        return _length;
    }

    /// <summary>Backfills the 16-bit length prefix opened by <see cref="BeginVector16"/>.</summary>
    public void EndVector16(int contentStart)
    {
        int contentLength = _length - contentStart;
        if (contentLength > 0xFFFF)
        {
            throw new InvalidOperationException("Vector length exceeds 16-bit prefix.");
        }

        BinaryPrimitives.WriteUInt16BigEndian(
            _buffer.AsSpan(contentStart - 2, 2),
            (ushort)contentLength);
    }

    /// <summary>Reserves a 24-bit length prefix and returns the content start offset.</summary>
    public int BeginVector24()
    {
        WriteUInt24(0);
        return _length;
    }

    /// <summary>Backfills the 24-bit length prefix opened by <see cref="BeginVector24"/>.</summary>
    public void EndVector24(int contentStart)
    {
        int contentLength = _length - contentStart;
        if (contentLength > 0xFFFFFF)
        {
            throw new InvalidOperationException("Vector length exceeds 24-bit prefix.");
        }

        BinaryHelpers.WriteUInt24BigEndian(
            _buffer.AsSpan(contentStart - 3, 3),
            (uint)contentLength);
    }

    /// <summary>Copies the bytes written so far into a new array.</summary>
    public byte[] ToArray() => _buffer.AsSpan(0, _length).ToArray();
}
