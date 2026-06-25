// Copyright (c) marcschier. All rights reserved.
// Licensed under the MIT License. See LICENSE in the project root for license information.

namespace Dtls;

/// <summary>
/// DTLS/TLS alert descriptions (RFC 8446 section 6, RFC 9147). Alerts signal closure or
/// errors during a DTLS connection.
/// </summary>
public enum DtlsAlert
{
    /// <summary>Notifies the peer of an orderly connection closure.</summary>
    CloseNotify = 0,

    /// <summary>An unexpected message was received.</summary>
    UnexpectedMessage = 10,

    /// <summary>A record was received with an incorrect authentication tag.</summary>
    BadRecordMac = 20,

    /// <summary>A handshake message exceeded the negotiated or configured limits.</summary>
    RecordOverflow = 22,

    /// <summary>The handshake could not negotiate an acceptable set of parameters.</summary>
    HandshakeFailure = 40,

    /// <summary>A certificate was corrupt or otherwise invalid.</summary>
    BadCertificate = 42,

    /// <summary>A certificate was not accepted by the peer.</summary>
    CertificateUnknown = 46,

    /// <summary>A received parameter was illegal.</summary>
    IllegalParameter = 47,

    /// <summary>The certificate authority could not be matched or trusted.</summary>
    UnknownCa = 48,

    /// <summary>A valid certificate or credential was rejected by policy.</summary>
    AccessDenied = 49,

    /// <summary>A message could not be decoded.</summary>
    DecodeError = 50,

    /// <summary>A cryptographic operation failed (for example, signature verification).</summary>
    DecryptError = 51,

    /// <summary>The protocol version proposed by the peer is not supported.</summary>
    ProtocolVersion = 70,

    /// <summary>Negotiation failed because security requirements were not met.</summary>
    InsufficientSecurity = 71,

    /// <summary>An internal error unrelated to the peer made the connection unusable.</summary>
    InternalError = 80,

    /// <summary>The handshake was cancelled.</summary>
    UserCanceled = 90,

    /// <summary>No application protocol could be negotiated.</summary>
    NoApplicationProtocol = 120,

    /// <summary>A required extension was missing.</summary>
    MissingExtension = 109,

    /// <summary>An unsupported extension was received.</summary>
    UnsupportedExtension = 110,

    /// <summary>The PSK identity was not recognised (RFC 4279 section 2).</summary>
    UnknownPskIdentity = 115,
}
