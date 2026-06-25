// Copyright (c) marcschier. All rights reserved.
// Licensed under the MIT License. See LICENSE in the project root for license information.

using System;
using System.Security.Cryptography;
using System.Text;

namespace Dtls.Crypto;

/// <summary>
/// The TLS 1.2 pseudo-random function (RFC 5246 section 5), implemented directly over the host's
/// HMAC primitive (the BCL, which delegates to the OS crypto library) so the key schedule never
/// diverges by platform. TLS 1.2 uses a single hash for the PRF — SHA-256 for most cipher suites,
/// SHA-384 for the SHA384 suites:
/// <c>PRF(secret, label, seed) = P_hash(secret, label || seed)</c> where
/// <c>P_hash(secret, S) = HMAC(secret, A(1) || S) || HMAC(secret, A(2) || S) || ...</c>,
/// <c>A(0) = S</c> and <c>A(i) = HMAC(secret, A(i-1))</c>.
/// </summary>
internal static class Tls12Prf
{
    /// <summary>
    /// Computes <paramref name="length"/> bytes of <c>PRF(secret, label, seed)</c> under
    /// <paramref name="hash"/> (RFC 5246 section 5).
    /// </summary>
    public static byte[] Prf(
        HashAlgorithmName hash,
        ReadOnlySpan<byte> secret,
        string label,
        ReadOnlySpan<byte> seed,
        int length)
    {
        if (label is null)
        {
            throw new ArgumentNullException(nameof(label));
        }

        byte[] labelBytes = Encoding.ASCII.GetBytes(label);
        byte[] labelAndSeed = new byte[labelBytes.Length + seed.Length];
        labelBytes.CopyTo(labelAndSeed, 0);
        seed.CopyTo(labelAndSeed.AsSpan(labelBytes.Length));

        byte[] result = PHash(hash, secret, labelAndSeed, length);
        CryptographicOperations.ZeroMemory(labelAndSeed);
        return result;
    }

    private static byte[] PHash(
        HashAlgorithmName hash,
        ReadOnlySpan<byte> secret,
        byte[] seed,
        int length)
    {
        if (length < 0)
        {
            throw new ArgumentOutOfRangeException(nameof(length));
        }

        byte[] key = secret.ToArray();
        byte[] output = new byte[length];
        int offset = 0;

        // A(0) = seed.
        byte[] a = seed;
        try
        {
            while (offset < length)
            {
                // A(i) = HMAC(secret, A(i-1)).
                using (IncrementalHash aHmac = IncrementalHash.CreateHMAC(hash, key))
                {
                    aHmac.AppendData(a);
                    byte[] next = aHmac.GetHashAndReset();
                    if (!ReferenceEquals(a, seed))
                    {
                        CryptographicOperations.ZeroMemory(a);
                    }

                    a = next;
                }

                // output_block = HMAC(secret, A(i) || seed).
                byte[] block;
                using (IncrementalHash blockHmac = IncrementalHash.CreateHMAC(hash, key))
                {
                    blockHmac.AppendData(a);
                    blockHmac.AppendData(seed);
                    block = blockHmac.GetHashAndReset();
                }

                int take = Math.Min(block.Length, length - offset);
                Array.Copy(block, 0, output, offset, take);
                CryptographicOperations.ZeroMemory(block);
                offset += take;
            }
        }
        finally
        {
            if (!ReferenceEquals(a, seed))
            {
                CryptographicOperations.ZeroMemory(a);
            }

            CryptographicOperations.ZeroMemory(key);
        }

        return output;
    }
}
