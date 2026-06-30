// Copyright (c) marcschier. All rights reserved.
// Licensed under the MIT License. See LICENSE in the project root for license information.

using System;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using Dtls.Crypto;
using Xunit;

namespace Dtls.UnitTests;

/// <summary>
/// Tests for <see cref="RawPublicKey"/>: exporting a certificate's SubjectPublicKeyInfo for an
/// RFC 7250 raw-public-key Certificate message and importing it back into an ECDSA or RSA key,
/// including rejection of malformed key material.
/// </summary>
public sealed class RawPublicKeyTests
{
    [Fact]
    public void ExportSubjectPublicKeyInfo_NullCertificate_Throws()
    {
        Assert.Throws<ArgumentNullException>(
            () => RawPublicKey.ExportSubjectPublicKeyInfo(null!));
    }

    [Fact]
    public void Export_ThenImport_EcdsaCertificate_RoundTripsToEcdsaKey()
    {
        using X509Certificate2 certificate = CreateEcdsaCertificate();

        byte[] spki = RawPublicKey.ExportSubjectPublicKeyInfo(certificate);

        using AsymmetricAlgorithm imported = RawPublicKey.ImportSubjectPublicKeyInfo(spki);
        ECDsa ecdsa = Assert.IsAssignableFrom<ECDsa>(imported);
        Assert.Equal(256, ecdsa.KeySize);
        Assert.Equal(spki, ecdsa.ExportSubjectPublicKeyInfo());
    }

    [Fact]
    public void Export_ThenImport_RsaCertificate_RoundTripsToRsaKey()
    {
        using X509Certificate2 certificate = CreateRsaCertificate();

        byte[] spki = RawPublicKey.ExportSubjectPublicKeyInfo(certificate);

        using AsymmetricAlgorithm imported = RawPublicKey.ImportSubjectPublicKeyInfo(spki);
        RSA rsa = Assert.IsAssignableFrom<RSA>(imported);
        Assert.Equal(spki, rsa.ExportSubjectPublicKeyInfo());
    }

    [Fact]
    public void ImportSubjectPublicKeyInfo_MalformedKey_ThrowsDtlsException()
    {
        byte[] garbage = { 0x01, 0x02, 0x03, 0x04 };

        Assert.Throws<DtlsException>(() => Import(garbage));

        static void Import(byte[] spki) =>
            RawPublicKey.ImportSubjectPublicKeyInfo(spki).Dispose();
    }

    [Fact]
    public void ImportSubjectPublicKeyInfo_EmptyInput_ThrowsDtlsException()
    {
        Assert.Throws<DtlsException>(() => Import());

        static void Import() =>
            RawPublicKey.ImportSubjectPublicKeyInfo(ReadOnlySpan<byte>.Empty).Dispose();
    }

    private static X509Certificate2 CreateEcdsaCertificate()
    {
        using ECDsa key = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var request = new CertificateRequest("CN=rawpublickey-test", key, HashAlgorithmName.SHA256);
        DateTimeOffset now = DateTimeOffset.UtcNow;
        return request.CreateSelfSigned(now.AddMinutes(-5), now.AddHours(1));
    }

    private static X509Certificate2 CreateRsaCertificate()
    {
        using RSA key = RSA.Create(2048);
        var request = new CertificateRequest(
            "CN=rawpublickey-test", key, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        DateTimeOffset now = DateTimeOffset.UtcNow;
        return request.CreateSelfSigned(now.AddMinutes(-5), now.AddHours(1));
    }
}
