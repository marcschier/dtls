// Copyright (c) marcschier. All rights reserved.
// Licensed under the MIT License. See LICENSE in the project root for license information.

using System;
using System.Threading;
using System.Threading.Tasks;
using Dtls.Internal;
using Xunit;

namespace Dtls.UnitTests;

/// <summary>
/// Tests for <see cref="AsyncDatagramChannel"/>: the single-producer/single-consumer FIFO that
/// backs the in-memory transport and the server demultiplexer. Covers ordering, blocking reads,
/// completion, post-completion and post-dispose writes, idempotent disposal, and cancellation.
/// </summary>
public sealed class AsyncDatagramChannelTests
{
    [Fact]
    public async Task ReadAsync_ReturnsDatagrams_InFifoOrder()
    {
        using var channel = new AsyncDatagramChannel();
        byte[] first = { 1, 2, 3 };
        byte[] second = { 4, 5, 6 };

        Assert.True(channel.Write(first));
        Assert.True(channel.Write(second));

        using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(5));
        Assert.Same(first, await channel.ReadAsync(cts.Token));
        Assert.Same(second, await channel.ReadAsync(cts.Token));
    }

    [Fact]
    public void Write_NullDatagram_Throws()
    {
        using var channel = new AsyncDatagramChannel();

        Assert.Throws<ArgumentNullException>(() => channel.Write(null!));
    }

    [Fact]
    public async Task ReadAsync_BlocksUntilWrite()
    {
        using var channel = new AsyncDatagramChannel();
        using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(5));

        ValueTask<byte[]?> pending = channel.ReadAsync(cts.Token);
        Assert.False(pending.IsCompleted);

        byte[] datagram = { 7, 8, 9 };
        Assert.True(channel.Write(datagram));

        Assert.Same(datagram, await pending);
    }

    [Fact]
    public async Task ReadAsync_AfterComplete_ReturnsNull()
    {
        using var channel = new AsyncDatagramChannel();
        channel.Complete();

        using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(5));
        Assert.Null(await channel.ReadAsync(cts.Token));
    }

    [Fact]
    public async Task ReadAsync_DrainsQueuedDatagrams_BeforeCompletion()
    {
        using var channel = new AsyncDatagramChannel();
        byte[] queued = { 1 };
        Assert.True(channel.Write(queued));
        channel.Complete();

        using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(5));
        Assert.Same(queued, await channel.ReadAsync(cts.Token));
        Assert.Null(await channel.ReadAsync(cts.Token));
    }

    [Fact]
    public void Write_AfterComplete_ReturnsFalse()
    {
        using var channel = new AsyncDatagramChannel();
        channel.Complete();

        Assert.False(channel.Write(new byte[] { 1 }));
    }

    [Fact]
    public void Write_AfterDispose_ReturnsFalse()
    {
        var channel = new AsyncDatagramChannel();
        channel.Dispose();

        Assert.False(channel.Write(new byte[] { 1 }));
    }

    [Fact]
    public void Dispose_IsIdempotent()
    {
        var channel = new AsyncDatagramChannel();
        channel.Dispose();

        channel.Dispose();
    }

    [Fact]
    public async Task ReadAsync_HonorsCanceledToken()
    {
        using var channel = new AsyncDatagramChannel();
        using var cts = new CancellationTokenSource();
        await cts.CancelAsync();

        await Assert.ThrowsAnyAsync<OperationCanceledException>(
            async () => await channel.ReadAsync(cts.Token));
    }
}
