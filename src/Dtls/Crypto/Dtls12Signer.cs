using System;
using System.Collections.Generic;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

namespace Dtls.Crypto;

/// <summary>
/// Produces and verifies the DTLS 1.2 ServerKeyExchange and CertificateVerify signatures
/// (RFC 5246 sections 7.4.3 and 7.4.8). The 2-byte <c>SignatureAndHashAlgorithm</c> selects the
/// hash (high byte) and signature algorithm (low byte: rsa=1, ecdsa=3). ECDSA signatures use the
/// DER-encoded ECDSA-Sig-Value; RSA uses RSASSA-PKCS1-v1_5 (TLS 1.2 default, unlike the PSS used
/// by TLS 1.3). The signed content (client_random || server_random || ServerECDHParams, or the
/// handshake_messages) is hashed by the signing primitive.
/// </summary>
/// <remarks>
/// The DER ECDSA <c>DSASignatureFormat</c> overloads require .NET 8 or later; on netstandard2.1 the
/// certificate path throws <see cref="PlatformNotSupportedException"/> (ECDHE already requires
/// .NET 7+).
/// </remarks>
internal static class Dtls12Signer
{
    private const byte RsaSignature = 1;
    private const byte EcdsaSignature = 3;

    /// <summary>Signs <paramref name="content"/> with the private key of the certificate.</summary>
    public static byte[] Sign(
        X509Certificate2 certificate,
        ushort algorithm,
        ReadOnlySpan<byte> content)
    {
        if (certificate is null)
        {
            throw new ArgumentNullException(nameof(certificate));
        }

        (HashAlgorithmName hash, bool ecdsa) = Decode(algorithm);
        byte[] data = content.ToArray();
        try
        {
            if (ecdsa)
            {
#if NET8_0_OR_GREATER
                using ECDsa key = certificate.GetECDsaPrivateKey()
                    ?? throw new DtlsException("The certificate has no ECDSA private key.");
                return key.SignData(data, hash, DSASignatureFormat.Rfc3279DerSequence);
#else
                throw new PlatformNotSupportedException(
                    "ECDSA DTLS 1.2 signatures require .NET 8 or later.");
#endif
            }

            using RSA rsa = certificate.GetRSAPrivateKey()
                ?? throw new DtlsException("The certificate has no RSA private key.");
            return rsa.SignData(data, hash, RSASignaturePadding.Pkcs1);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(data);
        }
    }

    /// <summary>
    /// Verifies a signature using the public key of <paramref name="certificate"/>.
    /// </summary>
    public static bool Verify(
        X509Certificate2 certificate,
        ushort algorithm,
        ReadOnlySpan<byte> content,
        ReadOnlySpan<byte> signature)
    {
        if (certificate is null)
        {
            throw new ArgumentNullException(nameof(certificate));
        }

        (_, bool ecdsa) = Decode(algorithm);
        if (ecdsa)
        {
            using ECDsa? key = certificate.GetECDsaPublicKey();
            return key is not null && Verify(key, algorithm, content, signature);
        }

        using RSA? rsa = certificate.GetRSAPublicKey();
        return rsa is not null && Verify(rsa, algorithm, content, signature);
    }

    /// <summary>
    /// Verifies a signature using a raw <paramref name="publicKey"/> (for example imported from a
    /// raw-public-key SubjectPublicKeyInfo).
    /// </summary>
    public static bool Verify(
        AsymmetricAlgorithm publicKey,
        ushort algorithm,
        ReadOnlySpan<byte> content,
        ReadOnlySpan<byte> signature)
    {
        if (publicKey is null)
        {
            throw new ArgumentNullException(nameof(publicKey));
        }

        (HashAlgorithmName hash, bool ecdsa) = Decode(algorithm);
        byte[] data = content.ToArray();
        byte[] sig = signature.ToArray();
        try
        {
            if (ecdsa)
            {
#if NET8_0_OR_GREATER
                if (publicKey is not ECDsa key)
                {
                    return false;
                }

                return key.VerifyData(data, sig, hash, DSASignatureFormat.Rfc3279DerSequence);
#else
                throw new PlatformNotSupportedException(
                    "ECDSA DTLS 1.2 signatures require .NET 8 or later.");
#endif
            }

            if (publicKey is not RSA rsa)
            {
                return false;
            }

            return rsa.VerifyData(data, sig, hash, RSASignaturePadding.Pkcs1);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(data);
        }
    }

    /// <summary>
    /// Selects a SignatureAndHashAlgorithm for <paramref name="certificate"/> from the peer's
    /// <paramref name="offered"/> list, preferring the certificate key's natural hash.
    /// </summary>
    public static bool TrySelectAlgorithm(
        X509Certificate2 certificate,
        IReadOnlyList<ushort> offered,
        out ushort algorithm)
    {
        algorithm = 0;

        using (ECDsa? ecdsa = certificate.GetECDsaPublicKey())
        {
            if (ecdsa is not null)
            {
                ushort candidate = ecdsa.KeySize switch
                {
                    256 => 0x0403,
                    384 => 0x0503,
                    521 => 0x0603,
                    _ => 0,
                };
                return candidate != 0 && Contains(offered, candidate, out algorithm);
            }
        }

        using (RSA? rsa = certificate.GetRSAPublicKey())
        {
            if (rsa is not null)
            {
                foreach (ushort candidate in new ushort[] { 0x0401, 0x0501, 0x0601 })
                {
                    if (Contains(offered, candidate, out algorithm))
                    {
                        return true;
                    }
                }
            }
        }

        return false;
    }

    private static bool Contains(IReadOnlyList<ushort> offered, ushort value, out ushort algorithm)
    {
        algorithm = value;
        if (offered is null || offered.Count == 0)
        {
            return true; // No explicit list: the algorithm is acceptable by default.
        }

        foreach (ushort candidate in offered)
        {
            if (candidate == value)
            {
                return true;
            }
        }

        algorithm = 0;
        return false;
    }

    private static (HashAlgorithmName Hash, bool Ecdsa) Decode(ushort algorithm)
    {
        byte hashByte = (byte)(algorithm >> 8);
        byte signatureByte = (byte)algorithm;

        HashAlgorithmName hash = hashByte switch
        {
            4 => HashAlgorithmName.SHA256,
            5 => HashAlgorithmName.SHA384,
            6 => HashAlgorithmName.SHA512,
            _ => throw new DtlsException("Unsupported DTLS 1.2 signature hash."),
        };

        if (signatureByte != RsaSignature && signatureByte != EcdsaSignature)
        {
            throw new DtlsException("Unsupported DTLS 1.2 signature algorithm.");
        }

        return (hash, signatureByte == EcdsaSignature);
    }
}
