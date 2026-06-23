using System;
using Dtls.Internal;

namespace Dtls.Routing;

/// <summary>
/// The routing decision produced by inspecting the first datagram of a DTLS connection.
/// </summary>
internal enum DtlsRoute
{
    /// <summary>
    /// The datagram could not be classified (not a ClientHello, malformed, or the
    /// ClientHello is fragmented such that the version is not yet observable). The caller
    /// should buffer/reassemble or drop the datagram rather than guess.
    /// </summary>
    Unknown,

    /// <summary>
    /// The ClientHello offers DTLS 1.3 via the <c>supported_versions</c> extension; route
    /// to the managed DTLS 1.3 engine.
    /// </summary>
    Managed13,

    /// <summary>
    /// The ClientHello offers only DTLS 1.2 or below; route to the native operating
    /// system DTLS stack.
    /// </summary>
    NativeLegacy,
}

/// <summary>
/// Inspects the first datagram of an incoming DTLS connection and decides whether it must
/// be handled by the managed DTLS 1.3 engine or the native (DTLS 1.0/1.2) backend. This
/// is the heart of the hybrid server design: a 1.3 ClientHello carries a
/// <c>supported_versions</c> extension (type 43) listing DTLS 1.3 (wire value 0xFEFC),
/// whereas a 1.0/1.2 ClientHello does not select 1.3 there.
/// </summary>
/// <remarks>
/// Parsing is strictly bounds-checked against the untrusted datagram. When the relevant
/// bytes are not present (for example, the ClientHello is fragmented across datagrams and
/// the extension has not arrived yet), the method returns <see cref="DtlsRoute.Unknown"/>
/// so the caller never misroutes a connection.
/// </remarks>
internal static class ClientHelloVersionPeek
{
    private const byte HandshakeContentType = 22;
    private const byte ClientHelloHandshakeType = 1;
    private const ushort SupportedVersionsExtensionType = 43;
    private const ushort Dtls13WireVersion = 0xFEFC;

    public static DtlsRoute Inspect(ReadOnlySpan<byte> datagram)
    {
        SpanReader reader = new(datagram);

        // DTLSPlaintext record header.
        if (!reader.TryReadByte(out byte contentType) || contentType != HandshakeContentType)
        {
            return DtlsRoute.Unknown;
        }

        if (!reader.TryReadUInt16(out _)           // legacy_record_version
            || !reader.TryReadUInt16(out _)        // epoch
            || !reader.TryReadUInt48(out _)        // sequence_number
            || !reader.TryReadUInt16(out ushort recordLength))
        {
            return DtlsRoute.Unknown;
        }

        if (!reader.TryReadBytes(recordLength, out ReadOnlySpan<byte> recordBody))
        {
            return DtlsRoute.Unknown;
        }

        return InspectHandshake(recordBody);
    }

    private static DtlsRoute InspectHandshake(ReadOnlySpan<byte> recordBody)
    {
        SpanReader reader = new(recordBody);

        if (!reader.TryReadByte(out byte handshakeType)
            || handshakeType != ClientHelloHandshakeType)
        {
            return DtlsRoute.Unknown;
        }

        if (!reader.TryReadUInt24(out uint messageLength)
            || !reader.TryReadUInt16(out _)            // message_seq
            || !reader.TryReadUInt24(out uint fragmentOffset)
            || !reader.TryReadUInt24(out uint fragmentLength))
        {
            return DtlsRoute.Unknown;
        }

        // Only the first, contiguous fragment is parsed for routing.
        if (fragmentOffset != 0)
        {
            return DtlsRoute.Unknown;
        }

        if (!reader.TryReadBytes((int)fragmentLength, out ReadOnlySpan<byte> body))
        {
            return DtlsRoute.Unknown;
        }

        bool fragmented = fragmentLength < messageLength;
        return InspectClientHelloBody(body, fragmented);
    }

    private static DtlsRoute InspectClientHelloBody(ReadOnlySpan<byte> body, bool fragmented)
    {
        SpanReader reader = new(body);

        if (!reader.TryReadUInt16(out _)              // legacy_version
            || !reader.TrySkip(32)                    // random
            || !reader.TryReadVector8(out _)          // legacy_session_id
            || !reader.TryReadVector8(out _)          // cookie (DTLS)
            || !reader.TryReadVector16(out _)         // cipher_suites
            || !reader.TryReadVector8(out _))         // legacy_compression_methods
        {
            return fragmented ? DtlsRoute.Unknown : DtlsRoute.NativeLegacy;
        }

        if (!reader.TryReadVector16(out ReadOnlySpan<byte> extensions))
        {
            // No extensions block: cannot be DTLS 1.3.
            return fragmented ? DtlsRoute.Unknown : DtlsRoute.NativeLegacy;
        }

        if (TryFindDtls13(extensions, out bool offersDtls13))
        {
            return offersDtls13 ? DtlsRoute.Managed13 : DtlsRoute.NativeLegacy;
        }

        // supported_versions not found in the observed bytes.
        return fragmented ? DtlsRoute.Unknown : DtlsRoute.NativeLegacy;
    }

    private static bool TryFindDtls13(ReadOnlySpan<byte> extensions, out bool offersDtls13)
    {
        offersDtls13 = false;
        SpanReader reader = new(extensions);

        while (reader.Remaining > 0)
        {
            if (!reader.TryReadUInt16(out ushort extensionType)
                || !reader.TryReadVector16(out ReadOnlySpan<byte> extensionData))
            {
                // Truncated extension: stop and report not-found.
                return false;
            }

            if (extensionType == SupportedVersionsExtensionType)
            {
                offersDtls13 = SupportedVersionsOffersDtls13(extensionData);
                return true;
            }
        }

        return false;
    }

    private static bool SupportedVersionsOffersDtls13(ReadOnlySpan<byte> extensionData)
    {
        SpanReader reader = new(extensionData);
        if (!reader.TryReadVector8(out ReadOnlySpan<byte> versions))
        {
            return false;
        }

        SpanReader versionReader = new(versions);
        while (versionReader.TryReadUInt16(out ushort version))
        {
            if (version == Dtls13WireVersion)
            {
                return true;
            }
        }

        return false;
    }
}
