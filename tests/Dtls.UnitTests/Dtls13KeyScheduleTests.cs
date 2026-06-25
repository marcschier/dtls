// Copyright (c) marcschier. All rights reserved.
// Licensed under the MIT License. See LICENSE in the project root for license information.

using System;
using System.Security.Cryptography;
using Dtls.Crypto;
using Dtls.Protocol.V13.Handshake;
using Xunit;

namespace Dtls.UnitTests;

/// <summary>
/// Self-consistency tests for the DTLS 1.3 key-schedule completion: Finished verify_data
/// and the PSK binder are computed on one side and verified on the other; tampering fails.
/// </summary>
public sealed class Dtls13KeyScheduleTests
{
    private static readonly HashAlgorithmName Sha256 = HashAlgorithmName.SHA256;

    [Fact]
    public void FullChain_DerivesDistinctSecrets()
    {
        byte[] transcript = TranscriptHashOf(0x11);
        byte[] ecdhe = Fill(32, 0x77);

        byte[] early = Dtls13KeySchedule.EarlySecret(Sha256, ReadOnlySpan<byte>.Empty);
        byte[] handshake = Dtls13KeySchedule.DeriveHandshakeSecret(Sha256, early, ecdhe);
        byte[] clientHs = Dtls13KeySchedule.DeriveClientHandshakeTrafficSecret(
            Sha256, handshake, transcript);
        byte[] serverHs = Dtls13KeySchedule.DeriveServerHandshakeTrafficSecret(
            Sha256, handshake, transcript);
        byte[] master = Dtls13KeySchedule.DeriveMasterSecret(Sha256, handshake);
        byte[] clientAp = Dtls13KeySchedule.DeriveClientApplicationTrafficSecret(
            Sha256, master, transcript);
        byte[] serverAp = Dtls13KeySchedule.DeriveServerApplicationTrafficSecret(
            Sha256, master, transcript);

        foreach (byte[] secret in new[] { early, handshake, clientHs, serverHs, master })
        {
            Assert.Equal(32, secret.Length);
        }

        Assert.NotEqual(clientHs, serverHs);
        Assert.NotEqual(clientAp, serverAp);
        Assert.NotEqual(handshake, master);
    }

    [Fact]
    public void Finished_ComputeThenVerify_IsSelfConsistent()
    {
        byte[] baseKey = Fill(32, 0x42);
        byte[] transcript = TranscriptHashOf(0x33);

        byte[] verifyData = Dtls13KeySchedule.ComputeVerifyData(Sha256, baseKey, transcript);
        Assert.True(Dtls13KeySchedule.VerifyFinished(Sha256, baseKey, transcript, verifyData));
    }

    [Fact]
    public void Finished_TamperedTranscript_FailsVerification()
    {
        byte[] baseKey = Fill(32, 0x42);
        byte[] transcript = TranscriptHashOf(0x33);
        byte[] verifyData = Dtls13KeySchedule.ComputeVerifyData(Sha256, baseKey, transcript);

        byte[] tampered = (byte[])transcript.Clone();
        tampered[0] ^= 0xFF;
        Assert.False(Dtls13KeySchedule.VerifyFinished(Sha256, baseKey, tampered, verifyData));

        byte[] tamperedData = (byte[])verifyData.Clone();
        tamperedData[5] ^= 0x01;
        Assert.False(Dtls13KeySchedule.VerifyFinished(Sha256, baseKey, transcript, tamperedData));
    }

    [Fact]
    public void Binder_ComputeOnClient_VerifyOnServer()
    {
        byte[] psk = Fill(32, 0x9A);
        byte[] truncatedTranscript = TranscriptHashOf(0x55);

        byte[] clientEarly = Dtls13KeySchedule.EarlySecret(Sha256, psk);
        byte[] clientBinderKey = Dtls13KeySchedule.DeriveExternalBinderKey(Sha256, clientEarly);
        byte[] binder = Dtls13KeySchedule.ComputeBinder(
            Sha256, clientBinderKey, truncatedTranscript);

        byte[] serverEarly = Dtls13KeySchedule.EarlySecret(Sha256, psk);
        byte[] serverBinderKey = Dtls13KeySchedule.DeriveExternalBinderKey(Sha256, serverEarly);
        Assert.True(Dtls13KeySchedule.VerifyBinder(
            Sha256, serverBinderKey, truncatedTranscript, binder));
    }

    [Fact]
    public void Binder_TamperedTranscript_FailsVerification()
    {
        byte[] psk = Fill(32, 0x9A);
        byte[] truncatedTranscript = TranscriptHashOf(0x55);

        byte[] early = Dtls13KeySchedule.EarlySecret(Sha256, psk);
        byte[] binderKey = Dtls13KeySchedule.DeriveExternalBinderKey(Sha256, early);
        byte[] binder = Dtls13KeySchedule.ComputeBinder(Sha256, binderKey, truncatedTranscript);

        byte[] tampered = (byte[])truncatedTranscript.Clone();
        tampered[1] ^= 0x80;
        Assert.False(Dtls13KeySchedule.VerifyBinder(Sha256, binderKey, tampered, binder));

        byte[] wrongPsk = Dtls13KeySchedule.DeriveExternalBinderKey(
            Sha256, Dtls13KeySchedule.EarlySecret(Sha256, Fill(32, 0x01)));
        Assert.False(Dtls13KeySchedule.VerifyBinder(
            Sha256, wrongPsk, truncatedTranscript, binder));
    }

    private static byte[] TranscriptHashOf(byte seed)
    {
        using IncrementalHash digest = IncrementalHash.CreateHash(Sha256);
        digest.AppendData(Fill(48, seed));
        return digest.GetHashAndReset();
    }

    private static byte[] Fill(int length, byte value)
    {
        byte[] buffer = new byte[length];
        Array.Fill(buffer, value);
        return buffer;
    }
}
