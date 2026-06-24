using System;
using System.Collections.Generic;
using System.Security.Cryptography;
using System.Threading;
using System.Threading.Tasks;
using Dtls.Transport;

namespace Dtls.Protocol.V13.Handshake;

/// <summary>
/// Drives the send/receive of DTLS 1.3 handshake flights with RFC 9147 section 5.8
/// retransmission. The current outbound flight (one or more datagrams) is buffered and resent
/// when the expected next flight does not arrive within a retransmission timeout (which doubles
/// on each retry, capped), or when a byte-identical retransmission of an already-consumed peer
/// flight arrives (signalling that our reply was lost). Inbound datagrams are de-duplicated by
/// content so a retransmitted peer flight is never delivered to the driver twice.
/// </summary>
internal sealed class Dtls13FlightTransceiver
{
    private readonly IDatagramTransport _transport;
    private readonly TimeSpan _initialTimeout;
    private readonly TimeSpan _maxTimeout;
    private readonly int _maxRetransmissions;
    private readonly List<byte[]> _outgoing = new();
    private readonly HashSet<string> _consumed = new();
    private bool _receivedSinceLastSend;

    public Dtls13FlightTransceiver(
        IDatagramTransport transport,
        TimeSpan initialTimeout,
        int maxRetransmissions)
    {
        _transport = transport;
        _initialTimeout = initialTimeout > TimeSpan.Zero ? initialTimeout : TimeSpan.FromSeconds(1);
        _maxTimeout = TimeSpan.FromSeconds(60);
        if (_maxTimeout < _initialTimeout)
        {
            _maxTimeout = _initialTimeout;
        }

        _maxRetransmissions = maxRetransmissions < 0 ? 0 : maxRetransmissions;
    }

    /// <summary>The underlying transport, for handing to the established connection.</summary>
    public IDatagramTransport Transport => _transport;

    /// <summary>
    /// Marks <paramref name="datagram"/> as already consumed so a later retransmission of it is
    /// recognised as a duplicate. Used to register the initial ClientHello the server received
    /// out of band (through the routing layer).
    /// </summary>
    public void Seed(ReadOnlySpan<byte> datagram)
    {
        _consumed.Add(Fingerprint(datagram));
    }

    /// <summary>
    /// Forgets a previously received datagram so a later retransmission of it is delivered again.
    /// Used when a driver receives a datagram it cannot process yet (for example the protected
    /// server flight arriving before the plaintext ServerHello over a lossy transport).
    /// </summary>
    public void Forget(ReadOnlySpan<byte> datagram)
    {
        _consumed.Remove(Fingerprint(datagram));
    }

    /// <summary>
    /// Adds one datagram to the current outbound flight and transmits it. Consecutive sends with
    /// no intervening receive accumulate into the same retransmittable flight; the first send
    /// after a receive starts a new flight.
    /// </summary>
    public async Task SendAsync(byte[] datagram, CancellationToken cancellationToken)
    {
        if (_receivedSinceLastSend)
        {
            _outgoing.Clear();
            _receivedSinceLastSend = false;
        }

        _outgoing.Add(datagram);
        await _transport.SendAsync(datagram, cancellationToken).ConfigureAwait(false);
    }

    /// <summary>
    /// Receives the next new (non-duplicate) inbound datagram, retransmitting the current
    /// outbound flight on timeout or when a duplicate peer flight arrives. Throws when the
    /// retransmission budget is exhausted.
    /// </summary>
    public async Task<byte[]> ReceiveFlightAsync(CancellationToken cancellationToken)
    {
        byte[]? datagram = await ReceiveCoreAsync(_maxRetransmissions, cancellationToken)
            .ConfigureAwait(false);
        if (datagram is null)
        {
            throw new DtlsException(
                "The DTLS handshake timed out waiting for the peer's next flight.");
        }

        return datagram;
    }

    /// <summary>
    /// Like <see cref="ReceiveFlightAsync"/> but returns <see langword="null"/> instead of
    /// throwing when the retransmission budget is exhausted. Used for the final ACK drain, where
    /// an unresponsive peer is presumed to have already completed the handshake.
    /// </summary>
    public Task<byte[]?> TryReceiveFlightAsync(
        int maxRetransmissions,
        CancellationToken cancellationToken)
    {
        return ReceiveCoreAsync(maxRetransmissions, cancellationToken);
    }

    private async Task<byte[]?> ReceiveCoreAsync(
        int maxRetransmissions,
        CancellationToken cancellationToken)
    {
        TimeSpan timeout = _initialTimeout;
        int retransmissions = 0;

        while (true)
        {
            byte[]? datagram = await ReceiveWithTimeoutAsync(timeout, cancellationToken)
                .ConfigureAwait(false);

            if (datagram is null)
            {
                if (_outgoing.Count == 0 || retransmissions >= maxRetransmissions)
                {
                    return null;
                }

                await RetransmitAsync(cancellationToken).ConfigureAwait(false);
                retransmissions++;
                timeout = Double(timeout, _maxTimeout);
                continue;
            }

            // A datagram arrived, so the peer is alive: reset the retransmission timer.
            timeout = _initialTimeout;
            retransmissions = 0;

            string fingerprint = Fingerprint(datagram);
            if (_consumed.Contains(fingerprint))
            {
                // A retransmission of a flight we already processed: our reply was lost, so resend
                // it. Bounded by the overall handshake cancellation token.
                await RetransmitAsync(cancellationToken).ConfigureAwait(false);
                continue;
            }

            _consumed.Add(fingerprint);
            _receivedSinceLastSend = true;
            return datagram;
        }
    }

    private async Task RetransmitAsync(CancellationToken cancellationToken)
    {
        foreach (byte[] datagram in _outgoing)
        {
            await _transport.SendAsync(datagram, cancellationToken).ConfigureAwait(false);
        }
    }

    private async Task<byte[]?> ReceiveWithTimeoutAsync(
        TimeSpan timeout,
        CancellationToken cancellationToken)
    {
        using CancellationTokenSource linked =
            CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        linked.CancelAfter(timeout);

        byte[] buffer = new byte[_transport.MaxDatagramSize];
        try
        {
            int received = await _transport.ReceiveAsync(buffer, linked.Token)
                .ConfigureAwait(false);
            if (received == 0)
            {
                throw new DtlsException("The peer closed the transport during the handshake.");
            }

            return buffer.AsSpan(0, received).ToArray();
        }
        catch (OperationCanceledException) when (!cancellationToken.IsCancellationRequested)
        {
            return null;
        }
    }

    private static TimeSpan Double(TimeSpan timeout, TimeSpan cap)
    {
        TimeSpan doubled = timeout + timeout;
        return doubled > cap ? cap : doubled;
    }

    private static string Fingerprint(ReadOnlySpan<byte> datagram)
    {
#if NET6_0_OR_GREATER
        Span<byte> hash = stackalloc byte[32];
        SHA256.HashData(datagram, hash);
        return Convert.ToBase64String(hash);
#else
        using SHA256 sha = SHA256.Create();
        return Convert.ToBase64String(sha.ComputeHash(datagram.ToArray()));
#endif
    }
}
