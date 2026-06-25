using System;
using System.Collections.Generic;
using Dtls.Internal;
using Dtls.Protocol.V13.Handshake;

namespace Dtls.Protocol.V12.Handshake;

/// <summary>
/// Encoders/decoders for the DTLS 1.2 ClientHello/ServerHello extensions used by the managed
/// engine: ec_point_formats (RFC 4492 / RFC 8422 section 5.1.2), extended_master_secret
/// (RFC 7627), and the classic signature_algorithms list (RFC 5246 section 7.4.1.4.1, two-byte
/// <c>SignatureAndHashAlgorithm</c> values). The supported_groups extension is shared with the
/// DTLS 1.3 codec (<see cref="SupportedGroupsExtension"/>).
/// </summary>
internal static class Dtls12Extensions
{
    /// <summary>The uncompressed EC point format (RFC 8422).</summary>
    private const byte UncompressedPointFormat = 0;

    /// <summary>
    /// Encodes the ec_point_formats extension_data advertising only the uncompressed format.
    /// </summary>
    public static byte[] EncodeEcPointFormats()
    {
        return new byte[] { 1, UncompressedPointFormat };
    }

    /// <summary>Encodes the (empty) extended_master_secret extension_data.</summary>
    public static byte[] EncodeExtendedMasterSecret()
    {
        return Array.Empty<byte>();
    }

    /// <summary>
    /// Encodes a signature_algorithms extension_data from a list of two-byte
    /// SignatureAndHashAlgorithm values.
    /// </summary>
    public static byte[] EncodeSignatureAlgorithms(IReadOnlyList<ushort> algorithms)
    {
        if (algorithms is null)
        {
            throw new ArgumentNullException(nameof(algorithms));
        }

        TlsWriter writer = new(2 + (algorithms.Count * 2));
        int listStart = writer.BeginVector16();
        for (int i = 0; i < algorithms.Count; i++)
        {
            writer.WriteUInt16(algorithms[i]);
        }

        writer.EndVector16(listStart);
        return writer.ToArray();
    }

    /// <summary>Parses a signature_algorithms extension_data into its two-byte values.</summary>
    public static bool TryParseSignatureAlgorithms(
        ReadOnlySpan<byte> data,
        out List<ushort> algorithms)
    {
        algorithms = new List<ushort>();

        SpanReader reader = new(data);
        if (!reader.TryReadVector16(out ReadOnlySpan<byte> list)
            || reader.Remaining != 0
            || (list.Length % 2) != 0
            || list.IsEmpty)
        {
            return false;
        }

        for (int i = 0; i < list.Length; i += 2)
        {
            algorithms.Add((ushort)((list[i] << 8) | list[i + 1]));
        }

        return true;
    }

    /// <summary>
    /// Whether <paramref name="extensions"/> contains the given <paramref name="type"/>.
    /// </summary>
    public static bool Has(
        IReadOnlyList<HandshakeExtension> extensions,
        ExtensionType type)
    {
        return ExtensionList.TryFind(extensions, type, out _);
    }
}
