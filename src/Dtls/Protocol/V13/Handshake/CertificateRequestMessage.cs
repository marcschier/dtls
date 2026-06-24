using System;
using System.Collections.Generic;
using Dtls.Internal;

namespace Dtls.Protocol.V13.Handshake;

/// <summary>
/// Encoder/decoder for the TLS 1.3 / DTLS 1.3 CertificateRequest handshake message body
/// (RFC 8446 section 4.3.2):
/// <c>opaque certificate_request_context&lt;0..2^8-1&gt;</c> followed by
/// <c>Extension extensions&lt;2..2^16-1&gt;</c>.
/// The server sends it to request client authentication; the only extension produced/consumed here
/// is <c>signature_algorithms</c>, which constrains the client's CertificateVerify scheme. The
/// certificate_request_context is always empty for handshake (non-post-handshake) authentication.
/// </summary>
internal static class CertificateRequestMessage
{
    /// <summary>
    /// Encodes a CertificateRequest body with an empty context and a single
    /// <c>signature_algorithms</c> extension listing <paramref name="schemes"/>.
    /// </summary>
    public static byte[] Encode(IReadOnlyList<SignatureScheme> schemes)
    {
        if (schemes is null)
        {
            throw new ArgumentNullException(nameof(schemes));
        }

        TlsWriter writer = new();
        writer.WriteByte(0); // empty certificate_request_context
        ExtensionList.Write(
            writer,
            new[]
            {
                new HandshakeExtension(
                    ExtensionType.SignatureAlgorithms,
                    SignatureAlgorithmsExtension.Encode(schemes)),
            });
        return writer.ToArray();
    }

    /// <summary>
    /// Parses a CertificateRequest body, returning the offered <c>signature_algorithms</c>.
    /// </summary>
    public static bool TryParse(ReadOnlySpan<byte> body, out List<SignatureScheme> schemes)
    {
        schemes = new List<SignatureScheme>();

        if (body.Length < 1)
        {
            return false;
        }

        int contextLength = body[0];
        if (1 + contextLength > body.Length)
        {
            return false;
        }

        ReadOnlySpan<byte> extensionsBlock = body.Slice(1 + contextLength);
        if (!ExtensionList.TryParse(extensionsBlock, out List<HandshakeExtension> extensions))
        {
            return false;
        }

        if (!ExtensionList.TryFind(
                extensions, ExtensionType.SignatureAlgorithms, out HandshakeExtension extension))
        {
            return false;
        }

        return SignatureAlgorithmsExtension.TryParse(extension.Data, out schemes);
    }
}
