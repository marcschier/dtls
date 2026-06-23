namespace Dtls.Protocol.V13.Handshake;

/// <summary>
/// The TLS 1.3 / DTLS 1.3 handshake message types (RFC 8446 section 4, RFC 9147). The
/// values are the registered <c>HandshakeType</c> codes carried in the handshake header.
/// </summary>
internal enum HandshakeType : byte
{
    /// <summary>client_hello (1).</summary>
    ClientHello = 1,

    /// <summary>server_hello (2). Also carries HelloRetryRequest via a magic random.</summary>
    ServerHello = 2,

    /// <summary>new_session_ticket (4).</summary>
    NewSessionTicket = 4,

    /// <summary>encrypted_extensions (8).</summary>
    EncryptedExtensions = 8,

    /// <summary>certificate (11).</summary>
    Certificate = 11,

    /// <summary>certificate_request (13).</summary>
    CertificateRequest = 13,

    /// <summary>certificate_verify (15).</summary>
    CertificateVerify = 15,

    /// <summary>finished (20).</summary>
    Finished = 20,

    /// <summary>key_update (24).</summary>
    KeyUpdate = 24,

    /// <summary>ack (26) (RFC 9147 section 7).</summary>
    Ack = 26,

    /// <summary>message_hash (254), used for the HelloRetryRequest transcript synthesis.</summary>
    MessageHash = 254,
}
