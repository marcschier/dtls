using System;
using Dtls.Crypto;
using Dtls.Protocol.V13.Handshake;
using Xunit;

namespace Dtls.UnitTests;

/// <summary>
/// Validates the ephemeral ECDHE key exchange over the NIST P-curves: two parties exchange
/// key_shares and derive an identical shared secret of the curve's coordinate length.
/// </summary>
public sealed class EcdheKeyExchangeTests
{
    [Theory]
    [InlineData(0x0017, 32)]
    [InlineData(0x0018, 48)]
    [InlineData(0x0019, 66)]
    public void TwoParties_DeriveIdenticalSecret(int groupValue, int coordinateLength)
    {
        NamedGroup group = (NamedGroup)groupValue;
        using EcdheKeyExchange client = EcdheKeyExchange.Create(group);
        using EcdheKeyExchange server = EcdheKeyExchange.Create(group);

        byte[] clientShare = client.ExportKeyShare();
        byte[] serverShare = server.ExportKeyShare();

        Assert.Equal(1 + (2 * coordinateLength), clientShare.Length);
        Assert.Equal(0x04, clientShare[0]);

        byte[] clientSecret = client.DeriveSharedSecret(serverShare);
        byte[] serverSecret = server.DeriveSharedSecret(clientShare);

        Assert.Equal(coordinateLength, clientSecret.Length);
        Assert.Equal(clientSecret, serverSecret);
    }

    [Fact]
    public void KeyShare_RoundTripsThroughExtension()
    {
        using EcdheKeyExchange client = EcdheKeyExchange.Create(NamedGroup.Secp256r1);
        byte[] share = client.ExportKeyShare();

        byte[] data = KeyShareExtension.EncodeServerHello(
            new KeyShareEntry(NamedGroup.Secp256r1, share));
        Assert.True(KeyShareExtension.TryParseServerHello(data, out KeyShareEntry parsed));

        Assert.Equal(NamedGroup.Secp256r1, parsed.Group);
        Assert.Equal(share, parsed.KeyExchange);
    }

    [Fact]
    public void DeriveSharedSecret_MalformedPoint_Throws()
    {
        using EcdheKeyExchange client = EcdheKeyExchange.Create(NamedGroup.Secp256r1);
        byte[] wrongLength = new byte[10];
        Assert.Throws<ArgumentException>(() => client.DeriveSharedSecret(wrongLength));
    }

    [Fact]
    public void IsSupported_OnlyNistCurves()
    {
        Assert.True(EcdheKeyExchange.IsSupported(NamedGroup.Secp256r1));
        Assert.True(EcdheKeyExchange.IsSupported(NamedGroup.Secp384r1));
        Assert.True(EcdheKeyExchange.IsSupported(NamedGroup.Secp521r1));
        Assert.False(EcdheKeyExchange.IsSupported(NamedGroup.X25519));
    }
}
