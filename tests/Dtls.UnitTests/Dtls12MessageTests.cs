// Copyright (c) marcschier. All rights reserved.
// Licensed under the MIT License. See LICENSE in the project root for license information.

using System;
using System.Collections.Generic;
using Dtls.Protocol.V12.Handshake;
using Xunit;

namespace Dtls.UnitTests;

/// <summary>
/// Round-trip tests for the DTLS 1.2 key-exchange and certificate message codecs (RFC 5246 /
/// RFC 4492): ServerKeyExchange (signed (EC)DHE), ClientKeyExchange, Certificate,
/// CertificateRequest, and CertificateVerify.
/// </summary>
public sealed class Dtls12MessageTests
{
    [Fact]
    public void SignedServerKeyExchange_RoundTrips_AndExposesSignedParams()
    {
        byte[] point = Bytes(0x04, 1, 2, 3, 4, 5, 6, 7, 8);
        byte[] ecdhParams = Dtls12ServerKeyExchange.EncodeEcdhParams(0x0017, point);
        byte[] signature = Bytes(0xAA, 0xBB, 0xCC, 0xDD);

        byte[] body = Dtls12ServerKeyExchange.EncodeSigned(ecdhParams, 0x0403, signature);

        Assert.True(Dtls12ServerKeyExchange.TryParseSigned(
            body,
            out ushort namedCurve,
            out byte[] parsedPoint,
            out ushort signatureAlgorithm,
            out byte[] parsedSignature,
            out byte[] parsedParams));

        Assert.Equal(0x0017, namedCurve);
        Assert.Equal(point, parsedPoint);
        Assert.Equal(0x0403, signatureAlgorithm);
        Assert.Equal(signature, parsedSignature);
        Assert.Equal(ecdhParams, parsedParams);
    }

    [Fact]
    public void ClientKeyExchange_Ecdhe_RoundTrips()
    {
        byte[] point = Bytes(0x04, 9, 8, 7, 6);
        byte[] body = Dtls12ClientKeyExchange.EncodeEcdhe(point);

        Assert.True(Dtls12ClientKeyExchange.TryParseEcdhe(body, out byte[] parsed));
        Assert.Equal(point, parsed);
    }

    [Fact]
    public void Certificate_RoundTrips()
    {
        byte[] cert0 = Bytes(0x30, 0x10, 1, 2, 3);
        byte[] cert1 = Bytes(0x30, 0x20, 9);
        byte[] body = Dtls12Certificate.Encode(new[] { cert0, cert1 });

        Assert.True(Dtls12Certificate.TryParse(body, out List<byte[]> parsed));
        Assert.Equal(2, parsed.Count);
        Assert.Equal(cert0, parsed[0]);
        Assert.Equal(cert1, parsed[1]);
    }

    [Fact]
    public void Certificate_Empty_RoundTrips()
    {
        byte[] body = Dtls12Certificate.Encode(Array.Empty<byte[]>());
        Assert.True(Dtls12Certificate.TryParse(body, out List<byte[]> parsed));
        Assert.Empty(parsed);
    }

    [Fact]
    public void CertificateRequest_RoundTrips()
    {
        byte[] body = Dtls12CertificateRequest.Encode(
            new[] { Dtls12CertificateRequest.EcdsaSign, Dtls12CertificateRequest.RsaSign },
            new ushort[] { 0x0403, 0x0401 });

        Assert.True(Dtls12CertificateRequest.TryParse(
            body, out List<byte> types, out List<ushort> algs));
        Assert.Equal(new List<byte> { 64, 1 }, types);
        Assert.Equal(new List<ushort> { 0x0403, 0x0401 }, algs);
    }

    [Fact]
    public void CertificateVerify_RoundTrips()
    {
        byte[] signature = Bytes(0x11, 0x22, 0x33, 0x44, 0x55);
        byte[] body = Dtls12CertificateVerify.Encode(0x0503, signature);

        Assert.True(Dtls12CertificateVerify.TryParse(
            body, out ushort algorithm, out byte[] parsed));
        Assert.Equal(0x0503, algorithm);
        Assert.Equal(signature, parsed);
    }

    private static byte[] Bytes(params byte[] values) => values;
}
