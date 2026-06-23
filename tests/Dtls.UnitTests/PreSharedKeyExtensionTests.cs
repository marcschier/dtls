using System;
using System.Collections.Generic;
using Dtls.Protocol.V13.Handshake;
using Xunit;

namespace Dtls.UnitTests;

/// <summary>
/// Encode/parse round-trips for the pre_shared_key extension (RFC 8446 section 4.2.11),
/// including the truncated ClientHello (identities only) used for binder computation.
/// </summary>
public sealed class PreSharedKeyExtensionTests
{
    private static List<PskIdentity> Identities()
    {
        return new List<PskIdentity>
        {
            new PskIdentity(new byte[] { 1, 2, 3, 4 }, 0),
            new PskIdentity(new byte[] { 9, 8, 7 }, 0x01020304),
        };
    }

    private static List<byte[]> Binders()
    {
        return new List<byte[]>
        {
            Fill(32, 0xAA),
            Fill(32, 0xBB),
        };
    }

    [Fact]
    public void TruncatedThenFull_AreConsistent()
    {
        List<PskIdentity> identities = Identities();
        List<byte[]> binders = Binders();

        byte[] identitiesBlock = PreSharedKeyExtension.EncodeIdentities(identities);
        byte[] bindersBlock = PreSharedKeyExtension.EncodeBinders(binders);
        byte[] full = PreSharedKeyExtension.EncodeClientHello(identities, binders);

        // The full extension_data is the identities block (the truncated ClientHello tail)
        // followed by the binders block.
        Assert.Equal(identitiesBlock.Length + bindersBlock.Length, full.Length);
        Assert.Equal(identitiesBlock, full.AsSpan(0, identitiesBlock.Length).ToArray());
        Assert.Equal(bindersBlock, full.AsSpan(identitiesBlock.Length).ToArray());

        // The binders-block length predictor agrees with the actual encoding, so the
        // truncation point can be located by subtracting it from the message length.
        List<int> binderLengths = new() { binders[0].Length, binders[1].Length };
        Assert.Equal(bindersBlock.Length, PreSharedKeyExtension.BindersBlockLength(binderLengths));
    }

    [Fact]
    public void ClientHello_RoundTrips()
    {
        List<PskIdentity> identities = Identities();
        List<byte[]> binders = Binders();
        byte[] full = PreSharedKeyExtension.EncodeClientHello(identities, binders);

        Assert.True(PreSharedKeyExtension.TryParseClientHello(
            full,
            out List<PskIdentity> parsedIdentities,
            out List<byte[]> parsedBinders));

        Assert.Equal(2, parsedIdentities.Count);
        Assert.Equal(identities[0].Identity, parsedIdentities[0].Identity);
        Assert.Equal(identities[1].ObfuscatedTicketAge, parsedIdentities[1].ObfuscatedTicketAge);
        Assert.Equal(binders[0], parsedBinders[0]);
        Assert.Equal(binders[1], parsedBinders[1]);
    }

    [Fact]
    public void ClientHello_BinderCountMismatch_Fails()
    {
        List<PskIdentity> identities = Identities();
        List<byte[]> binders = new() { Fill(32, 0xAA) };
        byte[] full = PreSharedKeyExtension.EncodeClientHello(identities, binders);
        Assert.False(PreSharedKeyExtension.TryParseClientHello(full, out _, out _));
    }

    [Fact]
    public void ClientHello_Truncated_Fails()
    {
        byte[] full = PreSharedKeyExtension.EncodeClientHello(Identities(), Binders());
        for (int len = 0; len < full.Length; len++)
        {
            Assert.False(PreSharedKeyExtension.TryParseClientHello(
                full.AsSpan(0, len).ToArray(),
                out _,
                out _));
        }
    }

    [Fact]
    public void ServerHello_RoundTrips()
    {
        byte[] data = PreSharedKeyExtension.EncodeServerHello(3);
        Assert.True(PreSharedKeyExtension.TryParseServerHello(data, out ushort selected));
        Assert.Equal(3, selected);
    }

    [Fact]
    public void ServerHello_Oversized_Fails()
    {
        Assert.False(PreSharedKeyExtension.TryParseServerHello(
            new byte[] { 0x00, 0x03, 0x00 },
            out _));
    }

    private static byte[] Fill(int length, byte value)
    {
        byte[] buffer = new byte[length];
        Array.Fill(buffer, value);
        return buffer;
    }
}
