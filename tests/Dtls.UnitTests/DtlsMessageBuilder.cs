using System;
using System.Collections.Generic;

namespace Dtls.UnitTests;

/// <summary>
/// Builds minimal, well-formed DTLS handshake datagrams for tests. Kept deliberately
/// explicit (no production parsing reused) so tests exercise the real code under test.
/// </summary>
internal static class DtlsMessageBuilder
{
    public const byte HandshakeContentType = 22;

    /// <summary>
    /// Builds a single-record, single-fragment ClientHello datagram.
    /// </summary>
    /// <param name="offerDtls13">Include a supported_versions extension with DTLS 1.3.</param>
    /// <param name="extraVersions">Additional wire versions to list before DTLS 1.3.</param>
    /// <param name="fragmentOffset">The handshake fragment_offset to encode.</param>
    /// <param name="contentType">Record content type (override for non-handshake).</param>
    public static byte[] BuildClientHello(
        bool offerDtls13,
        IReadOnlyList<ushort>? extraVersions = null,
        uint fragmentOffset = 0,
        byte contentType = HandshakeContentType)
    {
        List<byte> extensions = new();
        if (offerDtls13 || extraVersions is { Count: > 0 })
        {
            List<byte> versionList = new();
            if (extraVersions is not null)
            {
                foreach (ushort v in extraVersions)
                {
                    AddUInt16(versionList, v);
                }
            }

            if (offerDtls13)
            {
                AddUInt16(versionList, 0xFEFC);
            }

            List<byte> extData = new() { (byte)versionList.Count };
            extData.AddRange(versionList);

            AddUInt16(extensions, 43); // supported_versions
            AddUInt16(extensions, (ushort)extData.Count);
            extensions.AddRange(extData);
        }

        List<byte> body = new();
        AddUInt16(body, 0xFEFD);                 // legacy_version = DTLS 1.2
        body.AddRange(new byte[32]);             // random
        body.Add(0x00);                          // legacy_session_id (empty)
        body.Add(0x00);                          // cookie (empty)
        AddUInt16(body, 0x0002);                 // cipher_suites length
        AddUInt16(body, 0x1301);                 // TLS_AES_128_GCM_SHA256
        body.Add(0x01);                          // compression methods length
        body.Add(0x00);                          // null compression
        AddUInt16(body, (ushort)extensions.Count);
        body.AddRange(extensions);

        List<byte> handshake = new() { 1 };      // client_hello
        AddUInt24(handshake, (uint)body.Count);  // length
        AddUInt16(handshake, 0);                 // message_seq
        AddUInt24(handshake, fragmentOffset);    // fragment_offset
        AddUInt24(handshake, (uint)body.Count);  // fragment_length
        handshake.AddRange(body);

        List<byte> record = new() { contentType };
        AddUInt16(record, 0xFEFD);               // legacy_record_version
        AddUInt16(record, 0);                    // epoch
        AddUInt48(record, 0);                    // sequence_number
        AddUInt16(record, (ushort)handshake.Count);
        record.AddRange(handshake);

        return record.ToArray();
    }

    private static void AddUInt16(List<byte> target, ushort value)
    {
        target.Add((byte)(value >> 8));
        target.Add((byte)value);
    }

    private static void AddUInt24(List<byte> target, uint value)
    {
        target.Add((byte)(value >> 16));
        target.Add((byte)(value >> 8));
        target.Add((byte)value);
    }

    private static void AddUInt48(List<byte> target, ulong value)
    {
        target.Add((byte)(value >> 40));
        target.Add((byte)(value >> 32));
        target.Add((byte)(value >> 24));
        target.Add((byte)(value >> 16));
        target.Add((byte)(value >> 8));
        target.Add((byte)value);
    }
}
