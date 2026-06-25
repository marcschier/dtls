// Copyright (c) marcschier. All rights reserved.
// Licensed under the MIT License. See LICENSE in the project root for license information.

using System;
using System.Security.Cryptography;
using Dtls.Crypto;
using Xunit;

namespace Dtls.UnitTests;

/// <summary>
/// Tests the DTLS 1.2 key schedule (RFC 5246 / RFC 4279 / RFC 5489): master-secret length, the
/// AEAD key-block split, Finished verify_data, and the PSK pre_master_secret structure.
/// </summary>
public sealed class Dtls12KeyScheduleTests
{
    private static readonly HashAlgorithmName Sha256 = HashAlgorithmName.SHA256;

    [Fact]
    public void MasterSecret_Is48Bytes_AndDeterministic()
    {
        byte[] pms = RandomNumberGenerator.GetBytes(32);
        byte[] cr = RandomNumberGenerator.GetBytes(32);
        byte[] sr = RandomNumberGenerator.GetBytes(32);

        byte[] master = Dtls12KeySchedule.MasterSecret(Sha256, pms, cr, sr);
        byte[] master2 = Dtls12KeySchedule.MasterSecret(Sha256, pms, cr, sr);

        Assert.Equal(48, master.Length);
        Assert.Equal(master, master2);
    }

    [Fact]
    public void KeyBlock_SplitsClientAndServerKeysAndSalts()
    {
        byte[] master = RandomNumberGenerator.GetBytes(48);
        byte[] cr = RandomNumberGenerator.GetBytes(32);
        byte[] sr = RandomNumberGenerator.GetBytes(32);

        Dtls12KeyBlock block = Dtls12KeySchedule.KeyBlock(Sha256, master, sr, cr, keyLength: 16);

        Assert.Equal(16, block.ClientWriteKey.Length);
        Assert.Equal(16, block.ServerWriteKey.Length);
        Assert.Equal(4, block.ClientWriteSalt.Length);
        Assert.Equal(4, block.ServerWriteSalt.Length);
        Assert.NotEqual(block.ClientWriteKey, block.ServerWriteKey);
    }

    [Fact]
    public void VerifyData_Is12Bytes_AndLabelDependent()
    {
        byte[] master = RandomNumberGenerator.GetBytes(48);
        byte[] handshakeHash = RandomNumberGenerator.GetBytes(32);

        byte[] client = Dtls12KeySchedule.VerifyData(Sha256, master, handshakeHash, true);
        byte[] server = Dtls12KeySchedule.VerifyData(Sha256, master, handshakeHash, false);

        Assert.Equal(12, client.Length);
        Assert.Equal(12, server.Length);
        Assert.NotEqual(client, server);
    }

    [Fact]
    public void PlainPskPreMasterSecret_HasZeroOtherSecretAndPsk()
    {
        byte[] psk = { 1, 2, 3, 4 };

        byte[] pms = Dtls12KeySchedule.PlainPskPreMasterSecret(psk);

        // struct { opaque other_secret<0..2^16-1>; opaque psk<0..2^16-1>; } with other_secret =
        // zeros(psk.length).
        Assert.Equal(2 + psk.Length + 2 + psk.Length, pms.Length);
        Assert.Equal(0, pms[0]);
        Assert.Equal(psk.Length, pms[1]);
        for (int i = 0; i < psk.Length; i++)
        {
            Assert.Equal(0, pms[2 + i]);
        }

        int pskOffset = 2 + psk.Length;
        Assert.Equal(0, pms[pskOffset]);
        Assert.Equal(psk.Length, pms[pskOffset + 1]);
        Assert.Equal(psk, pms.AsSpan(pskOffset + 2).ToArray());
    }

    [Fact]
    public void EcdhePskPreMasterSecret_PrependsEcdheSecret()
    {
        byte[] ecdhe = { 9, 9, 9 };
        byte[] psk = { 7, 7 };

        byte[] pms = Dtls12KeySchedule.EcdhePskPreMasterSecret(ecdhe, psk);

        Assert.Equal(2 + ecdhe.Length + 2 + psk.Length, pms.Length);
        Assert.Equal(ecdhe.Length, pms[1]);
        Assert.Equal(ecdhe, pms.AsSpan(2, ecdhe.Length).ToArray());
    }
}
