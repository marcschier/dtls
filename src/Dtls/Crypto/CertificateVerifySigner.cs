// Copyright (c) marcschier. All rights reserved.
// Licensed under the MIT License. See LICENSE in the project root for license information.

using System;
using System.Collections.Generic;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using Dtls.Protocol.V13.Handshake;

namespace Dtls.Crypto;

/// <summary>
/// Produces and verifies the TLS 1.3 CertificateVerify signature (RFC 8446 section 4.4.3).
/// The signed content is <c>64 bytes of 0x20 || "TLS 1.3, server CertificateVerify" ||
/// 0x00 || Transcript-Hash(Handshake Context up to and including Certificate)</c>. ECDSA
/// signatures use the DER-encoded ECDSA-Sig-Value (r, s); RSA uses RSASSA-PSS. The
/// signature scheme is chosen from the server certificate key intersected with the
/// signature schemes the client offered.
/// </summary>
/// <remarks>
/// The ECDSA DER signature format requires the <c>DSASignatureFormat</c> overloads added in
/// .NET 8 for this code path; on netstandard2.1 the certificate handshake throws
/// <see cref="PlatformNotSupportedException"/> (and ECDHE already requires .NET 7+).
/// </remarks>
internal static class CertificateVerifySigner
{
    private const string ServerContextString = "TLS 1.3, server CertificateVerify";
    private const string ClientContextString = "TLS 1.3, client CertificateVerify";
    private const int ContextPadLength = 64;

    /// <summary>
    /// Selects a CertificateVerify signature scheme for <paramref name="certificate"/> from
    /// the client's <paramref name="offered"/> schemes, or returns <see langword="false"/>
    /// when no mutually supported scheme exists.
    /// </summary>
    public static bool TrySelectScheme(
        X509Certificate2 certificate,
        IReadOnlyList<SignatureScheme> offered,
        out SignatureScheme scheme)
    {
        if (certificate is null)
        {
            throw new ArgumentNullException(nameof(certificate));
        }

        if (offered is null)
        {
            throw new ArgumentNullException(nameof(offered));
        }

        scheme = default;

        using ECDsa? ecdsa = certificate.GetECDsaPublicKey();
        if (ecdsa is not null)
        {
            SignatureScheme candidate = ecdsa.KeySize switch
            {
                256 => SignatureScheme.EcdsaSecp256r1Sha256,
                384 => SignatureScheme.EcdsaSecp384r1Sha384,
                _ => default,
            };

            if (candidate != default && Contains(offered, candidate))
            {
                scheme = candidate;
                return true;
            }

            return false;
        }

        using RSA? rsa = certificate.GetRSAPublicKey();
        if (rsa is not null)
        {
            if (Contains(offered, SignatureScheme.RsaPssRsaeSha256))
            {
                scheme = SignatureScheme.RsaPssRsaeSha256;
                return true;
            }

            if (Contains(offered, SignatureScheme.RsaPssRsaeSha384))
            {
                scheme = SignatureScheme.RsaPssRsaeSha384;
                return true;
            }
        }

        return false;
    }

    /// <summary>
    /// Signs the CertificateVerify content for <paramref name="transcriptHash"/> using the
    /// private key of <paramref name="certificate"/> and the chosen <paramref name="scheme"/>.
    /// </summary>
    public static byte[] Sign(
        X509Certificate2 certificate,
        SignatureScheme scheme,
        ReadOnlySpan<byte> transcriptHash,
        bool clientContext = false)
    {
        if (certificate is null)
        {
            throw new ArgumentNullException(nameof(certificate));
        }

        byte[] content = BuildSignedContent(transcriptHash, clientContext);
        try
        {
            HashAlgorithmName hashAlgorithm = HashFor(scheme);
            if (IsEcdsa(scheme))
            {
#if NET8_0_OR_GREATER
                using ECDsa key = certificate.GetECDsaPrivateKey()
                    ?? throw new DtlsException("The server certificate has no ECDSA private key.");
                return key.SignData(
                    content, hashAlgorithm, DSASignatureFormat.Rfc3279DerSequence);
#else
                throw new PlatformNotSupportedException(
                    "ECDSA CertificateVerify requires .NET 8 or later.");
#endif
            }

            using RSA rsa = certificate.GetRSAPrivateKey()
                ?? throw new DtlsException("The server certificate has no RSA private key.");
            return rsa.SignData(content, hashAlgorithm, RSASignaturePadding.Pss);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(content);
        }
    }

    /// <summary>
    /// Verifies a CertificateVerify <paramref name="signature"/> against
    /// <paramref name="transcriptHash"/> using the public key of
    /// <paramref name="certificate"/> and the announced <paramref name="scheme"/>.
    /// </summary>
    public static bool Verify(
        X509Certificate2 certificate,
        SignatureScheme scheme,
        ReadOnlySpan<byte> transcriptHash,
        ReadOnlySpan<byte> signature,
        bool clientContext = false)
    {
        if (certificate is null)
        {
            throw new ArgumentNullException(nameof(certificate));
        }

        if (IsEcdsa(scheme))
        {
            using ECDsa? key = certificate.GetECDsaPublicKey();
            return key is not null && Verify(key, scheme, transcriptHash, signature, clientContext);
        }

        using RSA? rsa = certificate.GetRSAPublicKey();
        return rsa is not null && Verify(rsa, scheme, transcriptHash, signature, clientContext);
    }

    /// <summary>
    /// Verifies a CertificateVerify <paramref name="signature"/> against
    /// <paramref name="transcriptHash"/> using a raw <paramref name="publicKey"/> (an ECDSA or
    /// RSA key, for example imported from a raw-public-key SubjectPublicKeyInfo) and the
    /// announced <paramref name="scheme"/>.
    /// </summary>
    public static bool Verify(
        AsymmetricAlgorithm publicKey,
        SignatureScheme scheme,
        ReadOnlySpan<byte> transcriptHash,
        ReadOnlySpan<byte> signature,
        bool clientContext = false)
    {
        if (publicKey is null)
        {
            throw new ArgumentNullException(nameof(publicKey));
        }

        byte[] content = BuildSignedContent(transcriptHash, clientContext);
        try
        {
            HashAlgorithmName hashAlgorithm = HashFor(scheme);
            if (IsEcdsa(scheme))
            {
#if NET8_0_OR_GREATER
                if (publicKey is not ECDsa key)
                {
                    return false;
                }

                return key.VerifyData(
                    content, signature, hashAlgorithm, DSASignatureFormat.Rfc3279DerSequence);
#else
                throw new PlatformNotSupportedException(
                    "ECDSA CertificateVerify requires .NET 8 or later.");
#endif
            }

            if (publicKey is not RSA rsa)
            {
                return false;
            }

            return rsa.VerifyData(content, signature, hashAlgorithm, RSASignaturePadding.Pss);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(content);
        }
    }

    private static byte[] BuildSignedContent(ReadOnlySpan<byte> transcriptHash, bool clientContext)
    {
        byte[] context = Encoding.ASCII.GetBytes(
            clientContext ? ClientContextString : ServerContextString);
        byte[] content = new byte[ContextPadLength + context.Length + 1 + transcriptHash.Length];
        Span<byte> span = content;
        span.Slice(0, ContextPadLength).Fill(0x20);
        context.CopyTo(span.Slice(ContextPadLength));
        span[ContextPadLength + context.Length] = 0x00;
        transcriptHash.CopyTo(span.Slice(ContextPadLength + context.Length + 1));
        return content;
    }

    private static bool IsEcdsa(SignatureScheme scheme) =>
        scheme is SignatureScheme.EcdsaSecp256r1Sha256 or SignatureScheme.EcdsaSecp384r1Sha384;

    private static HashAlgorithmName HashFor(SignatureScheme scheme) => scheme switch
    {
        SignatureScheme.EcdsaSecp256r1Sha256 => HashAlgorithmName.SHA256,
        SignatureScheme.RsaPssRsaeSha256 => HashAlgorithmName.SHA256,
        SignatureScheme.EcdsaSecp384r1Sha384 => HashAlgorithmName.SHA384,
        SignatureScheme.RsaPssRsaeSha384 => HashAlgorithmName.SHA384,
        _ => throw new DtlsException("Unsupported CertificateVerify signature scheme."),
    };

    private static bool Contains(IReadOnlyList<SignatureScheme> schemes, SignatureScheme scheme)
    {
        for (int i = 0; i < schemes.Count; i++)
        {
            if (schemes[i] == scheme)
            {
                return true;
            }
        }

        return false;
    }
}
