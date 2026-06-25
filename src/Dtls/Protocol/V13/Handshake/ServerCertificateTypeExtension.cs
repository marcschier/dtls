// Copyright (c) marcschier. All rights reserved.
// Licensed under the MIT License. See LICENSE in the project root for license information.

using System;
using System.Collections.Generic;
using Dtls.Internal;

namespace Dtls.Protocol.V13.Handshake;

/// <summary>
/// The server_certificate_type extension (RFC 7250, type 20). In the ClientHello it carries
/// an 8-bit length-prefixed list of <see cref="CertificateType"/> values the client supports
/// for the server's certificate; in EncryptedExtensions (per RFC 8446) the server echoes a
/// single selected <see cref="CertificateType"/> byte.
/// </summary>
internal static class ServerCertificateTypeExtension
{
    /// <summary>Encodes the ClientHello extension_data: a list of supported types.</summary>
    public static byte[] EncodeClientHello(IReadOnlyList<CertificateType> types)
    {
        if (types is null)
        {
            throw new ArgumentNullException(nameof(types));
        }

        TlsWriter writer = new(1 + types.Count);
        int listStart = writer.BeginVector8();
        for (int i = 0; i < types.Count; i++)
        {
            writer.WriteByte((byte)types[i]);
        }

        writer.EndVector8(listStart);
        return writer.ToArray();
    }

    /// <summary>Parses the ClientHello extension_data into the list of supported types.</summary>
    public static bool TryParseClientHello(ReadOnlySpan<byte> data, out List<CertificateType> types)
    {
        types = new List<CertificateType>();

        SpanReader reader = new(data);
        if (!reader.TryReadVector8(out ReadOnlySpan<byte> listBytes) || reader.Remaining != 0)
        {
            return false;
        }

        if (listBytes.IsEmpty)
        {
            return false;
        }

        for (int i = 0; i < listBytes.Length; i++)
        {
            types.Add((CertificateType)listBytes[i]);
        }

        return true;
    }

    /// <summary>Encodes the EncryptedExtensions extension_data: a single selected type.</summary>
    public static byte[] EncodeServerHello(CertificateType type)
    {
        return new[] { (byte)type };
    }

    /// <summary>Parses the EncryptedExtensions extension_data into the selected type.</summary>
    public static bool TryParseServerHello(ReadOnlySpan<byte> data, out CertificateType type)
    {
        type = default;

        SpanReader reader = new(data);
        if (!reader.TryReadByte(out byte value) || reader.Remaining != 0)
        {
            return false;
        }

        type = (CertificateType)value;
        return true;
    }
}
