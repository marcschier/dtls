using System;
using System.Security.Cryptography;

namespace Dtls.Crypto;

/// <summary>
/// HKDF (RFC 5869) implemented directly over the host's HMAC primitive. The HMAC
/// primitive is provided by the BCL (and therefore the host OS crypto library); only the
/// standard extract/expand construction is assembled here, identically on every target
/// framework so the key schedule never diverges by platform.
/// </summary>
internal static class Hkdf
{
    /// <summary>Returns the output length, in bytes, of the given hash algorithm.</summary>
    public static int HashLength(HashAlgorithmName hash)
    {
        if (hash == HashAlgorithmName.SHA256)
        {
            return 32;
        }

        if (hash == HashAlgorithmName.SHA384)
        {
            return 48;
        }

        if (hash == HashAlgorithmName.SHA512)
        {
            return 64;
        }

        throw new ArgumentOutOfRangeException(
            nameof(hash),
            hash,
            "Unsupported hash algorithm for HKDF.");
    }

    /// <summary>
    /// HKDF-Extract: derives a pseudorandom key from input keying material and a salt.
    /// </summary>
    public static byte[] Extract(
        HashAlgorithmName hash,
        ReadOnlySpan<byte> salt,
        ReadOnlySpan<byte> inputKeyingMaterial)
    {
        int hashLength = HashLength(hash);
        byte[] key = salt.IsEmpty ? new byte[hashLength] : salt.ToArray();
        using IncrementalHash hmac = IncrementalHash.CreateHMAC(hash, key);
        hmac.AppendData(inputKeyingMaterial.ToArray());
        return hmac.GetHashAndReset();
    }

    /// <summary>
    /// HKDF-Expand: expands a pseudorandom key into output keying material of the
    /// requested length.
    /// </summary>
    public static byte[] Expand(
        HashAlgorithmName hash,
        ReadOnlySpan<byte> pseudoRandomKey,
        ReadOnlySpan<byte> info,
        int length)
    {
        if (length < 0)
        {
            throw new ArgumentOutOfRangeException(nameof(length));
        }

        int hashLength = HashLength(hash);
        int blocks = (length + hashLength - 1) / hashLength;
        if (blocks > 255)
        {
            throw new ArgumentOutOfRangeException(
                nameof(length),
                "HKDF output length exceeds 255 hash blocks.");
        }

        byte[] prk = pseudoRandomKey.ToArray();
        byte[] infoBytes = info.ToArray();
        byte[] output = new byte[length];
        byte[] previous = Array.Empty<byte>();
        int offset = 0;

        for (int i = 1; i <= blocks; i++)
        {
            using IncrementalHash hmac = IncrementalHash.CreateHMAC(hash, prk);
            hmac.AppendData(previous);
            hmac.AppendData(infoBytes);
            hmac.AppendData(new[] { (byte)i });
            previous = hmac.GetHashAndReset();

            int take = Math.Min(hashLength, length - offset);
            Array.Copy(previous, 0, output, offset, take);
            offset += take;
        }

        CryptographicOperations.ZeroMemory(previous);
        return output;
    }
}
