// Copyright (c) marcschier. All rights reserved.
// Licensed under the MIT License. See LICENSE in the project root for license information.

using System;
using System.Threading;
using System.Threading.Tasks;
using Dtls.Transport;

namespace Dtls.IntegrationTests;

/// <summary>
/// A test decorator that injects deterministic, seeded packet loss and duplication on the send
/// path of an inner <see cref="IDatagramTransport"/>, used to exercise the DTLS 1.3 handshake
/// retransmission/ACK/duplicate-suppression machinery. Reordering is not modelled because the
/// DTLS handshake is strictly turn-based and the server's first flight relies on in-order
/// delivery of its two datagrams.
/// </summary>
internal sealed class LossyDatagramTransport : IDatagramTransport
{
    private readonly IDatagramTransport _inner;
    private readonly Random _random;
    private readonly double _dropProbability;
    private readonly double _duplicateProbability;
    private readonly object _lock = new();

    public LossyDatagramTransport(
        IDatagramTransport inner,
        int seed,
        double dropProbability,
        double duplicateProbability)
    {
        _inner = inner;
        _random = new Random(seed);
        _dropProbability = dropProbability;
        _duplicateProbability = duplicateProbability;
    }

    public int MaxDatagramSize => _inner.MaxDatagramSize;

    public async ValueTask SendAsync(
        ReadOnlyMemory<byte> datagram,
        CancellationToken cancellationToken = default)
    {
        double dropRoll;
        double duplicateRoll;
        lock (_lock)
        {
            dropRoll = _random.NextDouble();
            duplicateRoll = _random.NextDouble();
        }

        if (dropRoll < _dropProbability)
        {
            return;
        }

        await _inner.SendAsync(datagram, cancellationToken).ConfigureAwait(false);

        if (duplicateRoll < _duplicateProbability)
        {
            await _inner.SendAsync(datagram, cancellationToken).ConfigureAwait(false);
        }
    }

    public ValueTask<int> ReceiveAsync(
        Memory<byte> buffer,
        CancellationToken cancellationToken = default)
    {
        return _inner.ReceiveAsync(buffer, cancellationToken);
    }

    public void Dispose()
    {
        _inner.Dispose();
    }
}
