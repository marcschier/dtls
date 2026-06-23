using System;
using System.Security.Cryptography.X509Certificates;

namespace Dtls;

/// <summary>
/// Validates a peer certificate during the DTLS handshake. Return <see langword="true"/>
/// to accept the certificate or <see langword="false"/> to abort the handshake.
/// </summary>
/// <param name="certificate">The peer's end-entity certificate.</param>
/// <param name="chain">The built chain, when available.</param>
/// <param name="nameValidationFailed">
/// Whether the default identity (host name) check failed; callers may still accept based
/// on their own policy (for example, pinning).
/// </param>
public delegate bool DtlsRemoteCertificateValidation(
    X509Certificate2 certificate,
    X509Chain? chain,
    bool nameValidationFailed);

/// <summary>
/// Supplies a client-side pre-shared key for a given server identity hint.
/// </summary>
/// <param name="identityHint">The optional identity hint sent by the server.</param>
/// <returns>The PSK credential to use.</returns>
public delegate PskCredential DtlsPskClientCallback(string? identityHint);

/// <summary>
/// Resolves a server-side pre-shared key for a client-presented identity.
/// </summary>
/// <param name="identity">The PSK identity presented by the client.</param>
/// <returns>
/// The key bytes for the identity, or an empty buffer to reject the connection.
/// </returns>
public delegate ReadOnlyMemory<byte> DtlsPskServerCallback(ReadOnlyMemory<byte> identity);

/// <summary>
/// Validates a peer raw public key (RFC 7250). The argument is the DER-encoded
/// SubjectPublicKeyInfo. Return <see langword="true"/> to accept (typically by pinning).
/// </summary>
/// <param name="subjectPublicKeyInfo">The DER-encoded SubjectPublicKeyInfo.</param>
public delegate bool DtlsRawPublicKeyValidation(ReadOnlyMemory<byte> subjectPublicKeyInfo);
