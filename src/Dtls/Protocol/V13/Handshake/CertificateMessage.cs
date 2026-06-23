using System;
using System.Collections.Generic;
using Dtls.Internal;

namespace Dtls.Protocol.V13.Handshake;

/// <summary>
/// The Certificate message body (RFC 8446 section 4.4.2):
/// <c>certificate_request_context&lt;0..255&gt;</c> followed by a 24-bit length-prefixed list
/// of <c>CertificateEntry</c> structures, each carrying a DER-encoded X.509 certificate
/// (<c>cert_data&lt;1..2^24-1&gt;</c>) and an <c>extensions&lt;0..2^16-1&gt;</c> block. The
/// managed handshake emits an empty request context (server authentication) and empty
/// per-entry extensions.
/// </summary>
internal static class CertificateMessage
{
    /// <summary>
    /// Encodes a Certificate body with an empty certificate_request_context and one entry
    /// per supplied DER certificate (extensions empty), in chain order.
    /// </summary>
    public static byte[] Encode(IReadOnlyList<byte[]> derCertificates)
    {
        if (derCertificates is null)
        {
            throw new ArgumentNullException(nameof(derCertificates));
        }

        TlsWriter writer = new(256);

        int contextStart = writer.BeginVector8();
        writer.EndVector8(contextStart);

        int listStart = writer.BeginVector24();
        for (int i = 0; i < derCertificates.Count; i++)
        {
            byte[] der = derCertificates[i];
            if (der is null || der.Length == 0)
            {
                throw new ArgumentException(
                    "A certificate entry was empty.", nameof(derCertificates));
            }

            int certStart = writer.BeginVector24();
            writer.WriteBytes(der);
            writer.EndVector24(certStart);

            int extStart = writer.BeginVector16();
            writer.EndVector16(extStart);
        }

        writer.EndVector24(listStart);
        return writer.ToArray();
    }

    /// <summary>
    /// Parses a Certificate body, returning the request context and the DER certificate
    /// bytes of each entry (entry extensions are ignored).
    /// </summary>
    public static bool TryParse(
        ReadOnlySpan<byte> body,
        out byte[] requestContext,
        out List<byte[]> derCertificates)
    {
        requestContext = Array.Empty<byte>();
        derCertificates = new List<byte[]>();

        SpanReader reader = new(body);
        if (!reader.TryReadVector8(out ReadOnlySpan<byte> context)
            || !reader.TryReadVector24(out ReadOnlySpan<byte> listBytes)
            || reader.Remaining != 0)
        {
            return false;
        }

        requestContext = context.ToArray();

        SpanReader inner = new(listBytes);
        while (inner.Remaining > 0)
        {
            if (!inner.TryReadVector24(out ReadOnlySpan<byte> certData)
                || certData.IsEmpty
                || !inner.TryReadVector16(out _))
            {
                requestContext = Array.Empty<byte>();
                derCertificates = new List<byte[]>();
                return false;
            }

            derCertificates.Add(certData.ToArray());
        }

        return true;
    }
}
