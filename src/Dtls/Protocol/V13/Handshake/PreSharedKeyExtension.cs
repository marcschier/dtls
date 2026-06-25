// Copyright (c) marcschier. All rights reserved.
// Licensed under the MIT License. See LICENSE in the project root for license information.

using System;
using System.Collections.Generic;
using Dtls.Internal;

namespace Dtls.Protocol.V13.Handshake;

/// <summary>
/// A PSK identity offered in a ClientHello (RFC 8446 section 4.2.11):
/// <c>identity&lt;1..2^16-1&gt; || obfuscated_ticket_age(uint32)</c>.
/// </summary>
internal readonly struct PskIdentity
{
    public PskIdentity(byte[] identity, uint obfuscatedTicketAge)
    {
        if (identity is null)
        {
            throw new ArgumentNullException(nameof(identity));
        }

        if (identity.Length is < 1 or > ushort.MaxValue)
        {
            throw new ArgumentException("Identity length out of range.", nameof(identity));
        }

        Identity = identity;
        ObfuscatedTicketAge = obfuscatedTicketAge;
    }

    /// <summary>The opaque PSK identity label (e.g. a ticket).</summary>
    public byte[] Identity { get; }

    /// <summary>The obfuscated ticket age (0 for externally established PSKs).</summary>
    public uint ObfuscatedTicketAge { get; }
}

/// <summary>
/// Encoder/decoder for the pre_shared_key extension (RFC 8446 section 4.2.11, type 41).
/// The ClientHello form (<c>OfferedPsks</c>) is split into an "identities" block and a
/// "binders" block so the truncated ClientHello required for binder computation
/// (section 4.2.11.2) can be produced: the binder transcript covers the message up to but
/// not including the binders list, with all length fields set as if binders were present.
/// </summary>
internal static class PreSharedKeyExtension
{
    /// <summary>Writes the identities block (the part preceding the binders).</summary>
    public static byte[] EncodeIdentities(IReadOnlyList<PskIdentity> identities)
    {
        if (identities is null)
        {
            throw new ArgumentNullException(nameof(identities));
        }

        TlsWriter writer = new(64);
        WriteIdentities(writer, identities);
        return writer.ToArray();
    }

    /// <summary>Writes the binders block (a vector16 of <c>opaque&lt;1..255&gt;</c>).</summary>
    public static byte[] EncodeBinders(IReadOnlyList<byte[]> binders)
    {
        if (binders is null)
        {
            throw new ArgumentNullException(nameof(binders));
        }

        TlsWriter writer = new(64);
        WriteBinders(writer, binders);
        return writer.ToArray();
    }

    /// <summary>
    /// Encodes the full ClientHello extension_data (<c>OfferedPsks</c>) as the identities
    /// block followed by the binders block.
    /// </summary>
    public static byte[] EncodeClientHello(
        IReadOnlyList<PskIdentity> identities,
        IReadOnlyList<byte[]> binders)
    {
        if (identities is null)
        {
            throw new ArgumentNullException(nameof(identities));
        }

        if (binders is null)
        {
            throw new ArgumentNullException(nameof(binders));
        }

        TlsWriter writer = new(128);
        WriteIdentities(writer, identities);
        WriteBinders(writer, binders);
        return writer.ToArray();
    }

    /// <summary>
    /// Returns the encoded length, in bytes, of a binders block holding binders of the
    /// supplied byte lengths (the vector16 prefix plus, per binder, a 1-byte length).
    /// </summary>
    public static int BindersBlockLength(IReadOnlyList<int> binderLengths)
    {
        if (binderLengths is null)
        {
            throw new ArgumentNullException(nameof(binderLengths));
        }

        int total = 2;
        for (int i = 0; i < binderLengths.Count; i++)
        {
            total += 1 + binderLengths[i];
        }

        return total;
    }

    /// <summary>
    /// Parses the ClientHello extension_data into its identities and binders. The binders
    /// are returned as raw byte arrays.
    /// </summary>
    public static bool TryParseClientHello(
        ReadOnlySpan<byte> data,
        out List<PskIdentity> identities,
        out List<byte[]> binders)
    {
        identities = new List<PskIdentity>();
        binders = new List<byte[]>();

        SpanReader reader = new(data);
        if (!reader.TryReadVector16(out ReadOnlySpan<byte> identitiesBytes))
        {
            return false;
        }

        SpanReader identityReader = new(identitiesBytes);
        while (identityReader.Remaining > 0)
        {
            if (!identityReader.TryReadVector16(out ReadOnlySpan<byte> identity)
                || identity.IsEmpty
                || !identityReader.TryReadUInt16(out ushort ageHigh)
                || !identityReader.TryReadUInt16(out ushort ageLow))
            {
                identities = new List<PskIdentity>();
                return false;
            }

            uint age = ((uint)ageHigh << 16) | ageLow;
            identities.Add(new PskIdentity(identity.ToArray(), age));
        }

        if (identities.Count == 0)
        {
            identities = new List<PskIdentity>();
            return false;
        }

        if (!reader.TryReadVector16(out ReadOnlySpan<byte> bindersBytes) || reader.Remaining != 0)
        {
            identities = new List<PskIdentity>();
            return false;
        }

        SpanReader binderReader = new(bindersBytes);
        while (binderReader.Remaining > 0)
        {
            if (!binderReader.TryReadVector8(out ReadOnlySpan<byte> binder) || binder.IsEmpty)
            {
                identities = new List<PskIdentity>();
                binders = new List<byte[]>();
                return false;
            }

            binders.Add(binder.ToArray());
        }

        if (binders.Count != identities.Count)
        {
            identities = new List<PskIdentity>();
            binders = new List<byte[]>();
            return false;
        }

        return true;
    }

    /// <summary>Encodes the ServerHello extension_data: the selected identity index.</summary>
    public static byte[] EncodeServerHello(ushort selectedIdentity)
    {
        byte[] data = new byte[2];
        data[0] = (byte)(selectedIdentity >> 8);
        data[1] = (byte)selectedIdentity;
        return data;
    }

    /// <summary>Parses the ServerHello extension_data into the selected identity index.</summary>
    public static bool TryParseServerHello(ReadOnlySpan<byte> data, out ushort selectedIdentity)
    {
        selectedIdentity = 0;

        SpanReader reader = new(data);
        if (!reader.TryReadUInt16(out selectedIdentity) || reader.Remaining != 0)
        {
            return false;
        }

        return true;
    }

    private static void WriteIdentities(TlsWriter writer, IReadOnlyList<PskIdentity> identities)
    {
        int listStart = writer.BeginVector16();
        for (int i = 0; i < identities.Count; i++)
        {
            PskIdentity identity = identities[i];
            int idStart = writer.BeginVector16();
            writer.WriteBytes(identity.Identity);
            writer.EndVector16(idStart);
            writer.WriteUInt32(identity.ObfuscatedTicketAge);
        }

        writer.EndVector16(listStart);
    }

    private static void WriteBinders(TlsWriter writer, IReadOnlyList<byte[]> binders)
    {
        int listStart = writer.BeginVector16();
        for (int i = 0; i < binders.Count; i++)
        {
            byte[] binder = binders[i];
            if (binder is null)
            {
                throw new ArgumentException("Binder entry is null.", nameof(binders));
            }

            if (binder.Length is < 1 or > 0xFF)
            {
                throw new ArgumentException("Binder length out of range.", nameof(binders));
            }

            int binderStart = writer.BeginVector8();
            writer.WriteBytes(binder);
            writer.EndVector8(binderStart);
        }

        writer.EndVector16(listStart);
    }
}
