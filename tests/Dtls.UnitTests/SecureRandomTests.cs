// Copyright (c) marcschier. All rights reserved.
// Licensed under the MIT License. See LICENSE in the project root for license information.

using System;
using Dtls.Crypto;
using Xunit;

namespace Dtls.UnitTests;

/// <summary>
/// Tests for <see cref="SecureRandom"/>: it must fill exactly the requested span with
/// high-entropy bytes and leave neighbouring memory untouched. A no-op or wrong-length
/// mutation would otherwise survive, because the handshake still completes when its random
/// nonces are all zero.
/// </summary>
public sealed class SecureRandomTests
{
    [Fact]
    public void Fill_ProducesNonZeroBytes()
    {
        byte[] buffer = new byte[32];

        SecureRandom.Fill(buffer);

        Assert.Contains(buffer, b => b != 0);
    }

    [Fact]
    public void Fill_TwoCalls_ProduceDifferentOutput()
    {
        byte[] first = new byte[32];
        byte[] second = new byte[32];

        SecureRandom.Fill(first);
        SecureRandom.Fill(second);

        Assert.NotEqual(first, second);
    }

    [Fact]
    public void Fill_DoesNotWriteOutsideTheSpan()
    {
        byte[] buffer = new byte[8];

        // Fill only the middle four bytes; the sentinel borders must stay zero.
        SecureRandom.Fill(buffer.AsSpan(2, 4));

        Assert.Equal(0, buffer[0]);
        Assert.Equal(0, buffer[1]);
        Assert.Equal(0, buffer[6]);
        Assert.Equal(0, buffer[7]);
    }

    [Fact]
    public void Fill_EmptySpan_DoesNotThrow()
    {
        SecureRandom.Fill(Span<byte>.Empty);
    }
}
