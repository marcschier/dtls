// Copyright (c) marcschier. All rights reserved.
// Licensed under the MIT License. See LICENSE in the project root for license information.

using System;

namespace Dtls.Internal;

/// <summary>
/// Big-endian read/write helpers for the 24-bit and 48-bit integers used by DTLS that
/// are not covered by <see cref="System.Buffers.Binary.BinaryPrimitives"/>.
/// </summary>
internal static class BinaryHelpers
{
    /// <summary>Reads a 24-bit big-endian unsigned integer.</summary>
    public static uint ReadUInt24BigEndian(ReadOnlySpan<byte> source)
    {
        if (source.Length < 3)
        {
            throw new ArgumentException("Need at least 3 bytes.", nameof(source));
        }

        return ((uint)source[0] << 16) | ((uint)source[1] << 8) | source[2];
    }

    /// <summary>Writes a 24-bit big-endian unsigned integer.</summary>
    public static void WriteUInt24BigEndian(Span<byte> destination, uint value)
    {
        if (destination.Length < 3)
        {
            throw new ArgumentException("Need at least 3 bytes.", nameof(destination));
        }

        if (value > 0xFFFFFF)
        {
            throw new ArgumentOutOfRangeException(nameof(value), "Value exceeds 24 bits.");
        }

        destination[0] = (byte)(value >> 16);
        destination[1] = (byte)(value >> 8);
        destination[2] = (byte)value;
    }

    /// <summary>Reads a 48-bit big-endian unsigned integer (DTLS record sequence number).</summary>
    public static ulong ReadUInt48BigEndian(ReadOnlySpan<byte> source)
    {
        if (source.Length < 6)
        {
            throw new ArgumentException("Need at least 6 bytes.", nameof(source));
        }

        return ((ulong)source[0] << 40)
            | ((ulong)source[1] << 32)
            | ((ulong)source[2] << 24)
            | ((ulong)source[3] << 16)
            | ((ulong)source[4] << 8)
            | source[5];
    }

    /// <summary>
    /// Writes a 48-bit big-endian unsigned integer (DTLS record sequence number).
    /// </summary>
    public static void WriteUInt48BigEndian(Span<byte> destination, ulong value)
    {
        if (destination.Length < 6)
        {
            throw new ArgumentException("Need at least 6 bytes.", nameof(destination));
        }

        if (value > 0xFFFFFFFFFFFF)
        {
            throw new ArgumentOutOfRangeException(nameof(value), "Value exceeds 48 bits.");
        }

        destination[0] = (byte)(value >> 40);
        destination[1] = (byte)(value >> 32);
        destination[2] = (byte)(value >> 24);
        destination[3] = (byte)(value >> 16);
        destination[4] = (byte)(value >> 8);
        destination[5] = (byte)value;
    }
}
