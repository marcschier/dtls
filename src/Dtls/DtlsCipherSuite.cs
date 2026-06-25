// Copyright (c) marcschier. All rights reserved.
// Licensed under the MIT License. See LICENSE in the project root for license information.

using System.Diagnostics.CodeAnalysis;

namespace Dtls;

/// <summary>
/// A DTLS 1.3 AEAD cipher suite that can be offered or required during the managed
/// handshake (RFC 9147 / RFC 8446 appendix B.4). Each member is the IANA-registered
/// identifier; whether a suite is actually negotiable depends on the target framework
/// (the AES-CCM suites require .NET 8 or later).
/// </summary>
[SuppressMessage(
    "Design",
    "CA1008:Enums should have zero value",
    Justification = "Members are the IANA-registered wire identifiers; 0x0000 is not a suite.")]
[SuppressMessage(
    "Design",
    "CA1028:Enum storage should be Int32",
    Justification = "The TLS cipher suite identifier is a 16-bit wire value (ushort).")]
public enum DtlsCipherSuite : ushort
{
    /// <summary>TLS_AES_128_GCM_SHA256 (0x1301). Supported on every target framework.</summary>
    Aes128GcmSha256 = 0x1301,

    /// <summary>TLS_AES_256_GCM_SHA384 (0x1302). Supported on every target framework.</summary>
    Aes256GcmSha384 = 0x1302,

    /// <summary>TLS_AES_128_CCM_SHA256 (0x1304). Negotiable only on .NET 8 or later.</summary>
    Aes128CcmSha256 = 0x1304,

    /// <summary>TLS_AES_128_CCM_8_SHA256 (0x1305). Negotiable only on .NET 8 or later.</summary>
    Aes128Ccm8Sha256 = 0x1305,
}
