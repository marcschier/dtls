using Dtls.Internal;
using Xunit;

namespace Dtls.UnitTests;

/// <summary>Behavioural tests for the DTLS anti-replay sliding window.</summary>
public sealed class AntiReplayWindowTests
{
    [Fact]
    public void FirstRecord_IsAccepted()
    {
        AntiReplayWindow window = new();
        Assert.True(window.TryAccept(0));
    }

    [Fact]
    public void Duplicate_IsRejected()
    {
        AntiReplayWindow window = new();
        Assert.True(window.TryAccept(5));
        Assert.False(window.TryAccept(5));
    }

    [Fact]
    public void IncreasingSequence_IsAccepted()
    {
        AntiReplayWindow window = new();
        for (ulong i = 0; i < 200; i++)
        {
            Assert.True(window.TryAccept(i));
        }
    }

    [Fact]
    public void OutOfOrder_WithinWindow_IsAccepted_ThenReplayRejected()
    {
        AntiReplayWindow window = new();
        Assert.True(window.TryAccept(100));
        Assert.True(window.TryAccept(98));
        Assert.True(window.TryAccept(99));

        Assert.False(window.TryAccept(100));
        Assert.False(window.TryAccept(98));
    }

    [Fact]
    public void TooOld_BeyondWindow_IsRejected()
    {
        AntiReplayWindow window = new();
        Assert.True(window.TryAccept(1000));

        ulong tooOld = 1000 - AntiReplayWindow.WindowSize;
        Assert.False(window.CanAccept(tooOld));
        Assert.False(window.TryAccept(tooOld));
    }

    [Fact]
    public void Edge_ExactlyAtWindowBoundary()
    {
        AntiReplayWindow window = new();
        Assert.True(window.TryAccept(1000));

        // Highest - (WindowSize - 1) is the oldest still representable position.
        ulong oldestRepresentable = 1000 - (AntiReplayWindow.WindowSize - 1);
        Assert.True(window.TryAccept(oldestRepresentable));
        Assert.False(window.TryAccept(oldestRepresentable));
    }

    [Fact]
    public void LargeJump_ResetsWindowButKeepsHighest()
    {
        AntiReplayWindow window = new();
        Assert.True(window.TryAccept(10));
        Assert.True(window.TryAccept(10_000));

        // Old positions are no longer representable and are treated as replays.
        Assert.False(window.CanAccept(10));

        // New high sequence numbers continue to be accepted.
        Assert.True(window.TryAccept(10_001));
    }

    [Fact]
    public void CanAccept_DoesNotMutateState()
    {
        AntiReplayWindow window = new();
        Assert.True(window.TryAccept(50));

        // Peeking a fresh sequence number must not consume it.
        Assert.True(window.CanAccept(51));
        Assert.True(window.CanAccept(51));
        Assert.True(window.TryAccept(51));
        Assert.False(window.CanAccept(51));
    }
}
