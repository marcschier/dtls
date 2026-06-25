// Copyright (c) marcschier. All rights reserved.
// Licensed under the MIT License. See LICENSE in the project root for license information.

using System;
using System.Security.Cryptography;
using Dtls.Protocol.V13;
using Dtls.Protocol.V13.Handshake;
using Xunit;

namespace Dtls.UnitTests;

/// <summary>
/// Tests the incremental transcript hash: message reconstruction, snapshotting, cloning,
/// and the partial (binder) transcript path (RFC 8446 section 4.4.1).
/// </summary>
public sealed class TranscriptHashTests
{
    private static readonly HashAlgorithmName Sha256 = HashAlgorithmName.SHA256;

    [Fact]
    public void AppendMessage_MatchesReconstructedHash()
    {
        byte[] body = { 0xDE, 0xAD, 0xBE, 0xEF };
        TranscriptHash transcript = new(Sha256);
        transcript.AppendMessage(HandshakeType.ClientHello, body);

        byte[] reconstructed = HandshakeMessage.ToTranscriptBytes(
            HandshakeType.ClientHello, body);
        byte[] expected = SHA256.HashData(reconstructed);

        Assert.Equal(expected, transcript.CurrentHash());
    }

    [Fact]
    public void Clone_IsIndependent()
    {
        TranscriptHash original = new(Sha256);
        original.AppendMessage(HandshakeType.ClientHello, new byte[] { 1, 2, 3 });

        TranscriptHash clone = original.Clone();
        byte[] snapshot = original.CurrentHash();

        clone.AppendMessage(HandshakeType.ServerHello, new byte[] { 4, 5, 6 });

        Assert.Equal(snapshot, original.CurrentHash());
        Assert.NotEqual(original.CurrentHash(), clone.CurrentHash());
    }

    [Fact]
    public void HashWithSuffix_EqualsAppendThenHash()
    {
        TranscriptHash transcript = new(Sha256);
        transcript.AppendMessage(HandshakeType.ClientHello, new byte[] { 9 });

        byte[] before = transcript.CurrentHash();
        byte[] suffix = { 0x11, 0x22, 0x33 };
        byte[] withSuffix = transcript.HashWithSuffix(suffix);

        TranscriptHash committed = transcript.Clone();
        committed.AppendRaw(suffix);

        Assert.Equal(committed.CurrentHash(), withSuffix);

        // HashWithSuffix must not mutate the transcript.
        Assert.Equal(before, transcript.CurrentHash());
    }

    [Fact]
    public void SynthesizeMessageHash_HasExpectedLayout()
    {
        byte[] clientHello1 = { 0x01, 0x02, 0x03 };
        byte[] synthetic = TranscriptHash.SynthesizeMessageHash(Sha256, clientHello1);

        Assert.Equal((byte)HandshakeType.MessageHash, synthetic[0]);
        Assert.Equal(0x00, synthetic[1]);
        Assert.Equal(0x00, synthetic[2]);
        Assert.Equal(0x20, synthetic[3]);

        byte[] expectedHash = SHA256.HashData(clientHello1);
        Assert.Equal(expectedHash, synthetic.AsSpan(4).ToArray());
    }
}
