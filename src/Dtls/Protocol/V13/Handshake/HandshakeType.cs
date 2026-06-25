// Copyright (c) marcschier. All rights reserved.
// Licensed under the MIT License. See LICENSE in the project root for license information.

namespace Dtls.Protocol.V13.Handshake;

/// <summary>
/// The TLS / DTLS handshake message types (RFC 8446 section 4, RFC 9147; RFC 5246/6347 for the
/// DTLS 1.2-only values). The values are the registered <c>HandshakeType</c> codes carried in the
/// handshake header and are shared by the managed DTLS 1.2 and 1.3 engines.
/// </summary>
internal enum HandshakeType : byte
{
    /// <summary>hello_request (0) (DTLS 1.2, RFC 5246).</summary>
    HelloRequest = 0,

    /// <summary>client_hello (1).</summary>
    ClientHello = 1,

    /// <summary>server_hello (2). Also carries HelloRetryRequest via a magic random.</summary>
    ServerHello = 2,

    /// <summary>hello_verify_request (3) (DTLS 1.2 cookie exchange, RFC 6347).</summary>
    HelloVerifyRequest = 3,

    /// <summary>new_session_ticket (4).</summary>
    NewSessionTicket = 4,

    /// <summary>encrypted_extensions (8).</summary>
    EncryptedExtensions = 8,

    /// <summary>certificate (11).</summary>
    Certificate = 11,

    /// <summary>server_key_exchange (12) (DTLS 1.2, RFC 5246).</summary>
    ServerKeyExchange = 12,

    /// <summary>certificate_request (13).</summary>
    CertificateRequest = 13,

    /// <summary>server_hello_done (14) (DTLS 1.2, RFC 5246).</summary>
    ServerHelloDone = 14,

    /// <summary>certificate_verify (15).</summary>
    CertificateVerify = 15,

    /// <summary>client_key_exchange (16) (DTLS 1.2, RFC 5246).</summary>
    ClientKeyExchange = 16,

    /// <summary>finished (20).</summary>
    Finished = 20,

    /// <summary>key_update (24).</summary>
    KeyUpdate = 24,

    /// <summary>ack (26) (RFC 9147 section 7).</summary>
    Ack = 26,

    /// <summary>message_hash (254), used for the HelloRetryRequest transcript synthesis.</summary>
    MessageHash = 254,
}
