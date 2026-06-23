using System;
using Dtls.Internal;

namespace Dtls.Protocol.V13.Handshake;

/// <summary>
/// The CertificateVerify message body (RFC 8446 section 4.4.3):
/// <c>algorithm(SignatureScheme, uint16) || signature&lt;0..2^16-1&gt;</c>.
/// </summary>
internal static class CertificateVerifyMessage
{
    /// <summary>Encodes the CertificateVerify body.</summary>
    public static byte[] Encode(SignatureScheme scheme, ReadOnlySpan<byte> signature)
    {
        if (signature.IsEmpty)
        {
            throw new ArgumentException("signature must not be empty.", nameof(signature));
        }

        TlsWriter writer = new(4 + signature.Length);
        writer.WriteUInt16((ushort)scheme);
        int sigStart = writer.BeginVector16();
        writer.WriteBytes(signature);
        writer.EndVector16(sigStart);
        return writer.ToArray();
    }

    /// <summary>Parses the CertificateVerify body.</summary>
    public static bool TryParse(
        ReadOnlySpan<byte> body,
        out SignatureScheme scheme,
        out byte[] signature)
    {
        scheme = default;
        signature = Array.Empty<byte>();

        SpanReader reader = new(body);
        if (!reader.TryReadUInt16(out ushort schemeValue)
            || !reader.TryReadVector16(out ReadOnlySpan<byte> sig)
            || reader.Remaining != 0
            || sig.IsEmpty)
        {
            return false;
        }

        scheme = (SignatureScheme)schemeValue;
        signature = sig.ToArray();
        return true;
    }
}
