// Copyright (c) marcschier. All rights reserved.
// Licensed under the MIT License. See LICENSE in the project root for license information.

using System;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using Dtls.Crypto;
using Dtls.Protocol.V13.Handshake;
using Xunit;

namespace Dtls.UnitTests;

/// <summary>
/// Tests for <see cref="CertificateVerifySigner"/>: the TLS 1.3 CertificateVerify signature
/// scheme selection (RFC 8446 section 4.2.3) and the sign/verify round-trip over the
/// context-padded transcript hash (section 4.4.3), for ECDSA and RSA-PSS keys.
/// </summary>
public sealed class CertificateVerifySignerTests
{
    [Fact]
    public void TrySelectScheme_NullCertificate_Throws()
    {
        SignatureScheme[] offered = { SignatureScheme.EcdsaSecp256r1Sha256 };

        Assert.Throws<ArgumentNullException>(
            () => CertificateVerifySigner.TrySelectScheme(null!, offered, out _));
    }

    [Fact]
    public void TrySelectScheme_NullOffered_Throws()
    {
        using X509Certificate2 certificate = CreateEcdsaCertificate(256);

        Assert.Throws<ArgumentNullException>(
            () => CertificateVerifySigner.TrySelectScheme(certificate, null!, out _));
    }

    [Fact]
    public void TrySelectScheme_P256Certificate_SelectsEcdsaSha256()
    {
        using X509Certificate2 certificate = CreateEcdsaCertificate(256);
        SignatureScheme[] offered =
        {
            SignatureScheme.RsaPssRsaeSha256,
            SignatureScheme.EcdsaSecp256r1Sha256,
        };

        Assert.True(CertificateVerifySigner.TrySelectScheme(
            certificate, offered, out SignatureScheme scheme));
        Assert.Equal(SignatureScheme.EcdsaSecp256r1Sha256, scheme);
    }

    [Fact]
    public void TrySelectScheme_P384Certificate_SelectsEcdsaSha384()
    {
        using X509Certificate2 certificate = CreateEcdsaCertificate(384);
        SignatureScheme[] offered = { SignatureScheme.EcdsaSecp384r1Sha384 };

        Assert.True(CertificateVerifySigner.TrySelectScheme(
            certificate, offered, out SignatureScheme scheme));
        Assert.Equal(SignatureScheme.EcdsaSecp384r1Sha384, scheme);
    }

    [Fact]
    public void TrySelectScheme_EcdsaCertificate_NotOffered_ReturnsFalse()
    {
        using X509Certificate2 certificate = CreateEcdsaCertificate(256);

        // Only RSA schemes are offered; an ECDSA certificate must not fall through to them.
        SignatureScheme[] offered =
        {
            SignatureScheme.RsaPssRsaeSha256,
            SignatureScheme.RsaPssRsaeSha384,
        };

        Assert.False(CertificateVerifySigner.TrySelectScheme(certificate, offered, out _));
    }

    [Fact]
    public void TrySelectScheme_P521Certificate_ReturnsFalse()
    {
        using X509Certificate2 certificate = CreateEcdsaCertificate(521);

        // P-521 has no enumerated scheme, so selection fails even though ECDSA schemes are offered.
        SignatureScheme[] offered =
        {
            SignatureScheme.EcdsaSecp256r1Sha256,
            SignatureScheme.EcdsaSecp384r1Sha384,
        };

        Assert.False(CertificateVerifySigner.TrySelectScheme(certificate, offered, out _));
    }

    [Fact]
    public void TrySelectScheme_RsaCertificate_PrefersSha256()
    {
        using X509Certificate2 certificate = CreateRsaCertificate();
        SignatureScheme[] offered =
        {
            SignatureScheme.RsaPssRsaeSha384,
            SignatureScheme.RsaPssRsaeSha256,
        };

        Assert.True(CertificateVerifySigner.TrySelectScheme(
            certificate, offered, out SignatureScheme scheme));
        Assert.Equal(SignatureScheme.RsaPssRsaeSha256, scheme);
    }

    [Fact]
    public void TrySelectScheme_RsaCertificate_FallsBackToSha384()
    {
        using X509Certificate2 certificate = CreateRsaCertificate();
        SignatureScheme[] offered = { SignatureScheme.RsaPssRsaeSha384 };

        Assert.True(CertificateVerifySigner.TrySelectScheme(
            certificate, offered, out SignatureScheme scheme));
        Assert.Equal(SignatureScheme.RsaPssRsaeSha384, scheme);
    }

    [Fact]
    public void TrySelectScheme_RsaCertificate_NoRsaSchemeOffered_ReturnsFalse()
    {
        using X509Certificate2 certificate = CreateRsaCertificate();
        SignatureScheme[] offered = { SignatureScheme.EcdsaSecp256r1Sha256 };

        Assert.False(CertificateVerifySigner.TrySelectScheme(certificate, offered, out _));
    }

    [Theory]
    [InlineData(256)]
    [InlineData(384)]
    public void EcdsaSignVerify_RoundTrips(int keySize)
    {
        SignatureScheme scheme = keySize == 256
            ? SignatureScheme.EcdsaSecp256r1Sha256
            : SignatureScheme.EcdsaSecp384r1Sha384;
        using X509Certificate2 certificate = CreateEcdsaCertificate(keySize);
        byte[] transcriptHash = RandomNumberGenerator.GetBytes(keySize == 256 ? 32 : 48);

        byte[] signature = CertificateVerifySigner.Sign(certificate, scheme, transcriptHash);

        Assert.True(CertificateVerifySigner.Verify(certificate, scheme, transcriptHash, signature));
    }

    [Fact]
    public void RsaSignVerify_RoundTrips()
    {
        using X509Certificate2 certificate = CreateRsaCertificate();
        byte[] transcriptHash = RandomNumberGenerator.GetBytes(32);

        byte[] signature = CertificateVerifySigner.Sign(
            certificate, SignatureScheme.RsaPssRsaeSha256, transcriptHash);

        Assert.True(CertificateVerifySigner.Verify(
            certificate, SignatureScheme.RsaPssRsaeSha256, transcriptHash, signature));
    }

    [Fact]
    public void Verify_RejectsTamperedSignature()
    {
        using X509Certificate2 certificate = CreateEcdsaCertificate(256);
        byte[] transcriptHash = RandomNumberGenerator.GetBytes(32);
        byte[] signature = CertificateVerifySigner.Sign(
            certificate, SignatureScheme.EcdsaSecp256r1Sha256, transcriptHash);

        signature[signature.Length - 1] ^= 0xFF;

        Assert.False(CertificateVerifySigner.Verify(
            certificate, SignatureScheme.EcdsaSecp256r1Sha256, transcriptHash, signature));
    }

    [Fact]
    public void Verify_RejectsTamperedTranscriptHash()
    {
        using X509Certificate2 certificate = CreateEcdsaCertificate(256);
        byte[] transcriptHash = RandomNumberGenerator.GetBytes(32);
        byte[] signature = CertificateVerifySigner.Sign(
            certificate, SignatureScheme.EcdsaSecp256r1Sha256, transcriptHash);

        transcriptHash[0] ^= 0xFF;

        Assert.False(CertificateVerifySigner.Verify(
            certificate, SignatureScheme.EcdsaSecp256r1Sha256, transcriptHash, signature));
    }

    [Fact]
    public void Verify_RejectsSignatureMadeWithDifferentContext()
    {
        // The 64-byte pad and the "client/server CertificateVerify" label are part of the signed
        // content, so a client-context signature must not verify under the server context.
        using X509Certificate2 certificate = CreateEcdsaCertificate(256);
        byte[] transcriptHash = RandomNumberGenerator.GetBytes(32);
        byte[] clientSignature = CertificateVerifySigner.Sign(
            certificate, SignatureScheme.EcdsaSecp256r1Sha256, transcriptHash, clientContext: true);

        Assert.False(CertificateVerifySigner.Verify(
            certificate, SignatureScheme.EcdsaSecp256r1Sha256, transcriptHash, clientSignature,
            clientContext: false));
        Assert.True(CertificateVerifySigner.Verify(
            certificate, SignatureScheme.EcdsaSecp256r1Sha256, transcriptHash, clientSignature,
            clientContext: true));
    }

    [Fact]
    public void Verify_WithImportedRawPublicKey_Succeeds()
    {
        using X509Certificate2 certificate = CreateEcdsaCertificate(256);
        byte[] transcriptHash = RandomNumberGenerator.GetBytes(32);
        byte[] signature = CertificateVerifySigner.Sign(
            certificate, SignatureScheme.EcdsaSecp256r1Sha256, transcriptHash);

        byte[] spki = RawPublicKey.ExportSubjectPublicKeyInfo(certificate);
        using AsymmetricAlgorithm publicKey = RawPublicKey.ImportSubjectPublicKeyInfo(spki);

        Assert.True(CertificateVerifySigner.Verify(
            publicKey, SignatureScheme.EcdsaSecp256r1Sha256, transcriptHash, signature));
    }

    [Fact]
    public void Verify_KeyTypeMismatch_ReturnsFalse()
    {
        // A key whose type does not match the announced scheme must be rejected, not throw.
        using X509Certificate2 ecdsaCertificate = CreateEcdsaCertificate(256);
        using X509Certificate2 rsaCertificate = CreateRsaCertificate();
        byte[] transcriptHash = RandomNumberGenerator.GetBytes(32);
        byte[] signature = CertificateVerifySigner.Sign(
            ecdsaCertificate, SignatureScheme.EcdsaSecp256r1Sha256, transcriptHash);

        using RSA rsaPublicKey = rsaCertificate.GetRSAPublicKey()!;
        using ECDsa ecdsaPublicKey = ecdsaCertificate.GetECDsaPublicKey()!;

        // RSA key announced with an ECDSA scheme.
        Assert.False(CertificateVerifySigner.Verify(
            rsaPublicKey, SignatureScheme.EcdsaSecp256r1Sha256, transcriptHash, signature));

        // ECDSA key announced with an RSA scheme.
        Assert.False(CertificateVerifySigner.Verify(
            ecdsaPublicKey, SignatureScheme.RsaPssRsaeSha256, transcriptHash, signature));
    }

    [Fact]
    public void Verify_NullPublicKey_Throws()
    {
        byte[] transcriptHash = RandomNumberGenerator.GetBytes(32);

        Assert.Throws<ArgumentNullException>(() => CertificateVerifySigner.Verify(
            (AsymmetricAlgorithm)null!, SignatureScheme.EcdsaSecp256r1Sha256,
            transcriptHash, transcriptHash));
    }

    [Fact]
    public void Sign_NullCertificate_Throws()
    {
        byte[] transcriptHash = RandomNumberGenerator.GetBytes(32);

        Assert.Throws<ArgumentNullException>(() => CertificateVerifySigner.Sign(
            null!, SignatureScheme.EcdsaSecp256r1Sha256, transcriptHash));
    }

    [Fact]
    public void Sign_UnsupportedScheme_ThrowsDtlsException()
    {
        using X509Certificate2 certificate = CreateRsaCertificate();
        byte[] transcriptHash = RandomNumberGenerator.GetBytes(32);

        Assert.Throws<DtlsException>(() => CertificateVerifySigner.Sign(
            certificate, (SignatureScheme)0x9999, transcriptHash));
    }

    private static X509Certificate2 CreateEcdsaCertificate(int keySize)
    {
        ECCurve curve = keySize switch
        {
            256 => ECCurve.NamedCurves.nistP256,
            384 => ECCurve.NamedCurves.nistP384,
            _ => ECCurve.NamedCurves.nistP521,
        };
        HashAlgorithmName hash = keySize switch
        {
            256 => HashAlgorithmName.SHA256,
            384 => HashAlgorithmName.SHA384,
            _ => HashAlgorithmName.SHA512,
        };
        using ECDsa key = ECDsa.Create(curve);
        var request = new CertificateRequest("CN=certverify-test", key, hash);
        DateTimeOffset now = DateTimeOffset.UtcNow;
        return request.CreateSelfSigned(now.AddMinutes(-5), now.AddHours(1));
    }

    private static X509Certificate2 CreateRsaCertificate()
    {
        using RSA key = RSA.Create(2048);
        var request = new CertificateRequest(
            "CN=certverify-test", key, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        DateTimeOffset now = DateTimeOffset.UtcNow;
        return request.CreateSelfSigned(now.AddMinutes(-5), now.AddHours(1));
    }
}
