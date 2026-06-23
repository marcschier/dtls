using System;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

namespace Dtls.Crypto;

/// <summary>
/// Helpers for RFC 7250 raw public keys: exporting a DER-encoded SubjectPublicKeyInfo from a
/// server certificate's public key, and importing a SubjectPublicKeyInfo back into an
/// asymmetric key suitable for CertificateVerify verification.
/// </summary>
/// <remarks>
/// Raw public keys reuse the certificate CertificateVerify signature path, which requires
/// the ECDSA DER signature overloads added in .NET 8; on netstandard2.1 these helpers throw
/// <see cref="PlatformNotSupportedException"/>, consistent with the certificate handshake.
/// </remarks>
internal static class RawPublicKey
{
    /// <summary>
    /// Exports the DER-encoded SubjectPublicKeyInfo of <paramref name="certificate"/>'s public
    /// key, as carried in the single CertificateEntry of a raw-public-key Certificate message.
    /// </summary>
    public static byte[] ExportSubjectPublicKeyInfo(X509Certificate2 certificate)
    {
        if (certificate is null)
        {
            throw new ArgumentNullException(nameof(certificate));
        }

#if NET8_0_OR_GREATER
        return certificate.PublicKey.ExportSubjectPublicKeyInfo();
#else
        throw new PlatformNotSupportedException(
            "Raw public keys require .NET 8 or later.");
#endif
    }

    /// <summary>
    /// Imports a DER-encoded SubjectPublicKeyInfo into an <see cref="AsymmetricAlgorithm"/>
    /// (ECDSA or RSA) for verifying a raw-public-key CertificateVerify signature. The caller
    /// owns the returned instance and must dispose it.
    /// </summary>
    public static AsymmetricAlgorithm ImportSubjectPublicKeyInfo(ReadOnlySpan<byte> spki)
    {
#if NET8_0_OR_GREATER
        ECDsa ecdsa = ECDsa.Create();
        try
        {
            ecdsa.ImportSubjectPublicKeyInfo(spki, out _);
            return ecdsa;
        }
        catch (CryptographicException)
        {
            ecdsa.Dispose();
        }

        RSA rsa = RSA.Create();
        try
        {
            rsa.ImportSubjectPublicKeyInfo(spki, out _);
            return rsa;
        }
        catch (CryptographicException)
        {
            rsa.Dispose();
            throw new DtlsException(
                "The server raw public key was not a supported ECDSA or RSA key.");
        }
#else
        throw new PlatformNotSupportedException(
            "Raw public keys require .NET 8 or later.");
#endif
    }
}
