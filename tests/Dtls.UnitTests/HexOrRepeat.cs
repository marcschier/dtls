using System;

namespace Dtls.UnitTests;

/// <summary>Small helpers for building byte arrays used by test vectors.</summary>
internal static class HexOrRepeat
{
    /// <summary>
    /// Returns an array of <paramref name="count"/> copies of <paramref name="value"/>.
    /// </summary>
    public static byte[] Repeat(byte value, int count)
    {
        byte[] result = new byte[count];
        Array.Fill(result, value);
        return result;
    }

    /// <summary>Returns bytes [start, start+1, ...] of length <paramref name="count"/>.</summary>
    public static byte[] Range(byte start, int count)
    {
        byte[] result = new byte[count];
        for (int i = 0; i < count; i++)
        {
            result[i] = (byte)(start + i);
        }

        return result;
    }
}
