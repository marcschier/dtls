using System;
using System.Collections.Generic;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using Dtls.Crypto;
using Xunit;

namespace Dtls.UnitTests;

/// <summary>
/// Round-trip tests for <see cref="Dtls12Signer"/>: the DTLS 1.2 ServerKeyExchange /
/// CertificateVerify signing helper. ECDSA uses the DER ECDSA-Sig-Value and RSA uses
/// RSASSA-PKCS1-v1_5 (the TLS 1.2 default, distinct from the PSS used by TLS 1.3).
/// </summary>
public sealed class Dtls12SignerTests
{
    [Theory]
    [InlineData(0x0403)] // ecdsa_secp256r1_sha256
    public void EcdsaSignature_RoundTrips(ushort algorithm)
    {
        using X509Certificate2 certificate = CreateEcdsaCertificate();
        byte[] content = RandomNumberGenerator.GetBytes(96);

        byte[] signature = Dtls12Signer.Sign(certificate, algorithm, content);

        Assert.True(Dtls12Signer.Verify(certificate, algorithm, content, signature));
    }

    [Fact]
    public void RsaSignature_RoundTrips_WithPkcs1Padding()
    {
        using X509Certificate2 certificate = CreateRsaCertificate();
        byte[] content = RandomNumberGenerator.GetBytes(96);

        byte[] signature = Dtls12Signer.Sign(certificate, 0x0401, content);

        Assert.True(Dtls12Signer.Verify(certificate, 0x0401, content, signature));

        // A PSS verification must fail: TLS 1.2 mandates PKCS#1 v1.5 here.
        using RSA publicKey = certificate.GetRSAPublicKey()!;
        Assert.False(publicKey.VerifyData(
            content, signature, HashAlgorithmName.SHA256, RSASignaturePadding.Pss));
    }

    [Fact]
    public void Verify_RejectsTamperedContent()
    {
        using X509Certificate2 certificate = CreateEcdsaCertificate();
        byte[] content = RandomNumberGenerator.GetBytes(64);
        byte[] signature = Dtls12Signer.Sign(certificate, 0x0403, content);

        content[0] ^= 0xFF;

        Assert.False(Dtls12Signer.Verify(certificate, 0x0403, content, signature));
    }

    [Fact]
    public void Verify_WithRawPublicKey_Succeeds()
    {
        using X509Certificate2 certificate = CreateEcdsaCertificate();
        byte[] content = RandomNumberGenerator.GetBytes(48);
        byte[] signature = Dtls12Signer.Sign(certificate, 0x0403, content);

        using ECDsa publicKey = certificate.GetECDsaPublicKey()!;

        Assert.True(Dtls12Signer.Verify(publicKey, 0x0403, content, signature));
    }

    [Fact]
    public void TrySelectAlgorithm_PicksEcdsaSha256_ForP256Certificate()
    {
        using X509Certificate2 certificate = CreateEcdsaCertificate();
        IReadOnlyList<ushort> offered = new ushort[] { 0x0401, 0x0403, 0x0503 };

        Assert.True(Dtls12Signer.TrySelectAlgorithm(certificate, offered, out ushort algorithm));
        Assert.Equal(0x0403, algorithm);
    }

    [Fact]
    public void TrySelectAlgorithm_PicksRsaSha256_ForRsaCertificate()
    {
        using X509Certificate2 certificate = CreateRsaCertificate();
        IReadOnlyList<ushort> offered = new ushort[] { 0x0403, 0x0401 };

        Assert.True(Dtls12Signer.TrySelectAlgorithm(certificate, offered, out ushort algorithm));
        Assert.Equal(0x0401, algorithm);
    }

    [Fact]
    public void TrySelectAlgorithm_FailsWhenNoOfferedAlgorithmMatches()
    {
        using X509Certificate2 certificate = CreateEcdsaCertificate();
        IReadOnlyList<ushort> offered = new ushort[] { 0x0401, 0x0501 };

        Assert.False(Dtls12Signer.TrySelectAlgorithm(certificate, offered, out _));
    }

    private static X509Certificate2 CreateEcdsaCertificate()
    {
        using ECDsa key = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var request = new CertificateRequest(
            "CN=dtls12-signer-test", key, HashAlgorithmName.SHA256);
        DateTimeOffset now = DateTimeOffset.UtcNow;
        return request.CreateSelfSigned(now.AddMinutes(-5), now.AddHours(1));
    }

    private static X509Certificate2 CreateRsaCertificate()
    {
        using RSA key = RSA.Create(2048);
        var request = new CertificateRequest(
            "CN=dtls12-signer-test", key, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        DateTimeOffset now = DateTimeOffset.UtcNow;
        return request.CreateSelfSigned(now.AddMinutes(-5), now.AddHours(1));
    }
}
