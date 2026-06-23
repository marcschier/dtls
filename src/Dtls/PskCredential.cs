using System;

namespace Dtls;

/// <summary>
/// A pre-shared key credential: an identity and its associated symmetric key. Used by the
/// PSK authentication modes of DTLS 1.2 (RFC 4279) and DTLS 1.3 (RFC 8446 section 2.2),
/// which are common in IoT and CoAP deployments.
/// </summary>
/// <remarks>
/// The key material is referenced, not copied. Callers are responsible for the lifetime
/// of the underlying buffers and should clear them when no longer needed.
/// </remarks>
public readonly struct PskCredential : IEquatable<PskCredential>
{
    /// <summary>Initializes a new credential from an identity and key.</summary>
    /// <param name="identity">The PSK identity (often a UTF-8 string).</param>
    /// <param name="key">The pre-shared key bytes.</param>
    public PskCredential(ReadOnlyMemory<byte> identity, ReadOnlyMemory<byte> key)
    {
        Identity = identity;
        Key = key;
    }

    /// <summary>The PSK identity presented on the wire.</summary>
    public ReadOnlyMemory<byte> Identity { get; }

    /// <summary>The pre-shared key bytes.</summary>
    public ReadOnlyMemory<byte> Key { get; }

    /// <summary>Whether this credential carries a non-empty key.</summary>
    public bool HasKey => !Key.IsEmpty;

    /// <inheritdoc />
    public bool Equals(PskCredential other)
    {
        return Identity.Equals(other.Identity) && Key.Equals(other.Key);
    }

    /// <inheritdoc />
    public override bool Equals(object? obj)
    {
        return obj is PskCredential other && Equals(other);
    }

    /// <inheritdoc />
    public override int GetHashCode()
    {
        return HashCode.Combine(Identity, Key);
    }

    /// <summary>Equality operator.</summary>
    public static bool operator ==(PskCredential left, PskCredential right)
    {
        return left.Equals(right);
    }

    /// <summary>Inequality operator.</summary>
    public static bool operator !=(PskCredential left, PskCredential right)
    {
        return !left.Equals(right);
    }
}
