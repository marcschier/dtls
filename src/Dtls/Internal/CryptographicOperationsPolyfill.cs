// Copyright (c) marcschier. All rights reserved.
// Licensed under the MIT License. See LICENSE in the project root for license information.

#if NETSTANDARD2_0
using System;

namespace System.Security.Cryptography;

/// <summary>
/// Polyfill of <c>CryptographicOperations</c> for netstandard2.0, which does not ship the type
/// (it was introduced in netstandard2.1 / .NET Core 2.1). Supplies the two members the library
/// uses: <see cref="ZeroMemory"/> and constant-time <see cref="FixedTimeEquals"/>. Recognized by
/// name where the code does <c>using System.Security.Cryptography;</c>.
/// </summary>
internal static class CryptographicOperations
{
    /// <summary>
    /// Clears <paramref name="buffer"/> so secret material does not linger in memory.
    /// </summary>
    public static void ZeroMemory(Span<byte> buffer) => buffer.Clear();

    /// <summary>
    /// Compares two spans for equality in an amount of time that depends only on their length,
    /// not their contents, to avoid leaking secrets through timing side channels.
    /// </summary>
    public static bool FixedTimeEquals(ReadOnlySpan<byte> left, ReadOnlySpan<byte> right)
    {
        // The length is not considered secret, so an early length comparison is acceptable.
        if (left.Length != right.Length)
        {
            return false;
        }

        int accumulator = 0;
        for (int i = 0; i < left.Length; i++)
        {
            accumulator |= left[i] ^ right[i];
        }

        return accumulator == 0;
    }
}
#endif
