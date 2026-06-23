using System;

namespace Dtls.Internal;

/// <summary>
/// A DTLS anti-replay sliding window (RFC 6347 section 4.1.2.6, RFC 9147 section 4.5.1).
/// It tracks which record sequence numbers within a fixed window above the highest
/// authenticated record have already been seen, so replayed or duplicated records can be
/// discarded.
/// </summary>
/// <remarks>
/// The window holds <see cref="WindowSize"/> positions in a 64-bit bitmap. The intended
/// usage is two-phase: call <see cref="CanAccept"/> to cheaply reject obvious replays
/// before authentication, then call <see cref="MarkAccepted"/> only after the record's
/// authentication tag has been verified. Updating the window only post-authentication
/// prevents a forged high sequence number from advancing the window and causing valid
/// records to be dropped.
/// </remarks>
internal sealed class AntiReplayWindow
{
    /// <summary>The number of sequence positions tracked behind the highest record.</summary>
    public const int WindowSize = 64;

    private ulong _bitmap;
    private ulong _highest;
    private bool _seenAny;

    /// <summary>
    /// Returns whether <paramref name="sequenceNumber"/> could be a fresh (non-replayed)
    /// record. This does not modify the window.
    /// </summary>
    public bool CanAccept(ulong sequenceNumber)
    {
        if (!_seenAny || sequenceNumber > _highest)
        {
            return true;
        }

        ulong diff = _highest - sequenceNumber;
        if (diff >= WindowSize)
        {
            // Too old to verify against the window; treat as a replay.
            return false;
        }

        return (_bitmap & (1UL << (int)diff)) == 0;
    }

    /// <summary>
    /// Records that <paramref name="sequenceNumber"/> has been successfully
    /// authenticated, advancing the window if necessary.
    /// </summary>
    public void MarkAccepted(ulong sequenceNumber)
    {
        if (!_seenAny)
        {
            _seenAny = true;
            _highest = sequenceNumber;
            _bitmap = 1UL;
            return;
        }

        if (sequenceNumber > _highest)
        {
            ulong shift = sequenceNumber - _highest;
            _bitmap = shift >= WindowSize ? 1UL : (_bitmap << (int)shift) | 1UL;
            _highest = sequenceNumber;
            return;
        }

        ulong diff = _highest - sequenceNumber;
        if (diff < WindowSize)
        {
            _bitmap |= 1UL << (int)diff;
        }
    }

    /// <summary>
    /// Convenience helper that atomically checks and, if acceptable, marks the sequence
    /// number. Intended for tests and single-threaded callers that have already
    /// authenticated the record.
    /// </summary>
    public bool TryAccept(ulong sequenceNumber)
    {
        if (!CanAccept(sequenceNumber))
        {
            return false;
        }

        MarkAccepted(sequenceNumber);
        return true;
    }
}
