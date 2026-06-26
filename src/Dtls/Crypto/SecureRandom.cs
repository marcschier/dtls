// Copyright (c) marcschier. All rights reserved.
// Licensed under the MIT License. See LICENSE in the project root for license information.

using System;
using System.Security.Cryptography;

namespace Dtls.Crypto;

/// <summary>
/// Fills spans with cryptographically strong random bytes. On modern target frameworks this
/// forwards to <c>RandomNumberGenerator.Fill</c>; on netstandard2.0, which has
/// no span-based RNG API, it rents a temporary array, fills it with the host RNG, copies it into
/// the destination, and clears it.
/// </summary>
internal static class SecureRandom
{
    /// <summary>Fills <paramref name="data"/> with cryptographically strong random bytes.</summary>
    public static void Fill(Span<byte> data)
    {
#if NETSTANDARD2_0
        if (data.IsEmpty)
        {
            return;
        }

        byte[] buffer = new byte[data.Length];
        try
        {
            using (RandomNumberGenerator rng = RandomNumberGenerator.Create())
            {
                rng.GetBytes(buffer);
            }

            buffer.AsSpan().CopyTo(data);
        }
        finally
        {
            Array.Clear(buffer, 0, buffer.Length);
        }
#else
        RandomNumberGenerator.Fill(data);
#endif
    }
}
