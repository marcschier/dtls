using System;
using System.Security.Cryptography;
using Dtls.Protocol.V13.Handshake;

namespace Dtls.Crypto;

/// <summary>
/// An ephemeral ECDHE key exchange over the NIST P-curves (secp256r1/secp384r1/secp521r1)
/// for the DTLS 1.3 / TLS 1.3 key_share extension (RFC 8446 section 4.2.8). It wraps the
/// BCL <see cref="ECDiffieHellman"/>, exporting and importing TLS uncompressed-point
/// key shares (<c>0x04 || X || Y</c>) and computing the raw shared secret (the X
/// coordinate of the shared point, big-endian, padded to the curve's coordinate length).
/// </summary>
/// <remarks>
/// The shared-secret computation uses <c>ECDiffieHellman.DeriveRawSecretAgreement</c>, which
/// is available only on .NET 7 and later. On netstandard2.1 the managed handshake cannot
/// run, so <see cref="DeriveSharedSecret"/> throws <see cref="PlatformNotSupportedException"/>;
/// the record layer and wire codecs still compile and run on netstandard2.1. X25519 is not
/// exposed by the BCL across the supported targets, so only the NIST P-curves are offered.
/// </remarks>
internal sealed class EcdheKeyExchange : IDisposable
{
    private readonly ECDiffieHellman _ecdh;
    private readonly NamedGroup _group;
    private readonly ECCurve _curve;
    private readonly int _coordinateLength;
    private bool _disposed;

    private EcdheKeyExchange(NamedGroup group, ECCurve curve, int coordinateLength)
    {
        _group = group;
        _curve = curve;
        _coordinateLength = coordinateLength;
        _ecdh = ECDiffieHellman.Create(_curve);
    }

    /// <summary>The named group of this key exchange.</summary>
    public NamedGroup Group => _group;

    /// <summary>The curve coordinate length, in bytes (32, 48, or 66).</summary>
    public int CoordinateLength => _coordinateLength;

    /// <summary>The exported key_share length, in bytes (<c>1 + 2 * coordinate</c>).</summary>
    public int KeyShareLength => 1 + (2 * _coordinateLength);

    /// <summary>Whether <paramref name="group"/> is a supported NIST P-curve.</summary>
    public static bool IsSupported(NamedGroup group) =>
        TryGetCurve(group, out _, out _);

    /// <summary>
    /// Creates an ephemeral ECDHE key pair for the supplied <paramref name="group"/>.
    /// </summary>
    public static EcdheKeyExchange Create(NamedGroup group)
    {
        if (!TryGetCurve(group, out ECCurve curve, out int coordinateLength))
        {
            throw new NotSupportedException(
                "Unsupported named group for managed ECDHE: " + group + ".");
        }

        return new EcdheKeyExchange(group, curve, coordinateLength);
    }

    /// <summary>
    /// Exports this party's public key as a TLS key_share key_exchange: the uncompressed
    /// EC point <c>0x04 || X || Y</c> with fixed-length coordinates.
    /// </summary>
    public byte[] ExportKeyShare()
    {
        ThrowIfDisposed();

        ECParameters parameters = _ecdh.ExportParameters(false);
        byte[] result = new byte[KeyShareLength];
        result[0] = 0x04;
        CopyRightAligned(parameters.Q.X, result.AsSpan(1, _coordinateLength));
        CopyRightAligned(parameters.Q.Y, result.AsSpan(1 + _coordinateLength, _coordinateLength));
        return result;
    }

    /// <summary>
    /// Imports the peer's key_share and computes the raw ECDHE shared secret (the X
    /// coordinate of the shared point), big-endian and padded to the coordinate length.
    /// </summary>
    public byte[] DeriveSharedSecret(ReadOnlySpan<byte> peerKeyShare)
    {
        ThrowIfDisposed();

        if (peerKeyShare.Length != KeyShareLength || peerKeyShare[0] != 0x04)
        {
            throw new ArgumentException(
                "Peer key_share is not a valid uncompressed point.",
                nameof(peerKeyShare));
        }

#if NET7_0_OR_GREATER
        byte[] x = peerKeyShare.Slice(1, _coordinateLength).ToArray();
        byte[] y = peerKeyShare.Slice(1 + _coordinateLength, _coordinateLength).ToArray();

        ECParameters peerParameters = new()
        {
            Curve = _curve,
            Q = new ECPoint { X = x, Y = y },
        };
        peerParameters.Validate();

        using ECDiffieHellman peer = ECDiffieHellman.Create(peerParameters);
        using ECDiffieHellmanPublicKey peerPublicKey = peer.PublicKey;
        return _ecdh.DeriveRawSecretAgreement(peerPublicKey);
#else
        _ = peerKeyShare.Length;
        throw new PlatformNotSupportedException(
            "Managed DTLS 1.3 ECDHE requires .NET 7 or later.");
#endif
    }

    private void ThrowIfDisposed()
    {
        if (_disposed)
        {
            throw new ObjectDisposedException(nameof(EcdheKeyExchange));
        }
    }

    private static bool TryGetCurve(NamedGroup group, out ECCurve curve, out int coordinateLength)
    {
        switch (group)
        {
            case NamedGroup.Secp256r1:
                curve = ECCurve.NamedCurves.nistP256;
                coordinateLength = 32;
                return true;
            case NamedGroup.Secp384r1:
                curve = ECCurve.NamedCurves.nistP384;
                coordinateLength = 48;
                return true;
            case NamedGroup.Secp521r1:
                curve = ECCurve.NamedCurves.nistP521;
                coordinateLength = 66;
                return true;
            default:
                curve = default;
                coordinateLength = 0;
                return false;
        }
    }

    private static void CopyRightAligned(byte[]? source, Span<byte> destination)
    {
        destination.Clear();
        if (source is null || source.Length == 0)
        {
            return;
        }

        if (source.Length > destination.Length)
        {
            source.AsSpan(source.Length - destination.Length).CopyTo(destination);
            return;
        }

        source.CopyTo(destination.Slice(destination.Length - source.Length));
    }

    /// <inheritdoc />
    public void Dispose()
    {
        if (_disposed)
        {
            return;
        }

        _ecdh.Dispose();
        _disposed = true;
    }
}
