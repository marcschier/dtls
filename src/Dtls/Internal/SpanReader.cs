// Copyright (c) marcschier. All rights reserved.
// Licensed under the MIT License. See LICENSE in the project root for license information.

using System;
using System.Buffers.Binary;

namespace Dtls.Internal;

/// <summary>
/// A forward-only, bounds-checked reader over a <see cref="ReadOnlySpan{T}"/> of bytes.
/// Every read validates that enough bytes remain, so parsing untrusted network input can
/// never read out of bounds. All multi-byte integers are read big-endian (network order).
/// </summary>
internal ref struct SpanReader
{
    private readonly ReadOnlySpan<byte> _span;
    private int _position;

    public SpanReader(ReadOnlySpan<byte> span)
    {
        _span = span;
        _position = 0;
    }

    public readonly int Position => _position;

    public readonly int Remaining => _span.Length - _position;

    public bool TryReadByte(out byte value)
    {
        if (Remaining < 1)
        {
            value = 0;
            return false;
        }

        value = _span[_position];
        _position++;
        return true;
    }

    public bool TryReadUInt16(out ushort value)
    {
        if (Remaining < 2)
        {
            value = 0;
            return false;
        }

        value = BinaryPrimitives.ReadUInt16BigEndian(_span.Slice(_position, 2));
        _position += 2;
        return true;
    }

    public bool TryReadUInt24(out uint value)
    {
        if (Remaining < 3)
        {
            value = 0;
            return false;
        }

        value = BinaryHelpers.ReadUInt24BigEndian(_span.Slice(_position, 3));
        _position += 3;
        return true;
    }

    public bool TryReadUInt48(out ulong value)
    {
        if (Remaining < 6)
        {
            value = 0;
            return false;
        }

        value = BinaryHelpers.ReadUInt48BigEndian(_span.Slice(_position, 6));
        _position += 6;
        return true;
    }

    public bool TryReadBytes(int count, out ReadOnlySpan<byte> bytes)
    {
        if (count < 0 || Remaining < count)
        {
            bytes = default;
            return false;
        }

        bytes = _span.Slice(_position, count);
        _position += count;
        return true;
    }

    /// <summary>Reads an 8-bit length-prefixed vector (<c>opaque v&lt;0..255&gt;</c>).</summary>
    public bool TryReadVector8(out ReadOnlySpan<byte> bytes)
    {
        if (!TryReadByte(out byte length))
        {
            bytes = default;
            return false;
        }

        return TryReadBytes(length, out bytes);
    }

    /// <summary>Reads a 16-bit length-prefixed vector (<c>opaque v&lt;0..65535&gt;</c>).</summary>
    public bool TryReadVector16(out ReadOnlySpan<byte> bytes)
    {
        if (!TryReadUInt16(out ushort length))
        {
            bytes = default;
            return false;
        }

        return TryReadBytes(length, out bytes);
    }

    /// <summary>Reads a 24-bit length-prefixed vector (<c>opaque v&lt;0..2^24-1&gt;</c>).</summary>
    public bool TryReadVector24(out ReadOnlySpan<byte> bytes)
    {
        if (!TryReadUInt24(out uint length))
        {
            bytes = default;
            return false;
        }

        return TryReadBytes((int)length, out bytes);
    }

    public bool TrySkip(int count)
    {
        if (count < 0 || Remaining < count)
        {
            return false;
        }

        _position += count;
        return true;
    }
}
