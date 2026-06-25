// Copyright (c) marcschier. All rights reserved.
// Licensed under the MIT License. See LICENSE in the project root for license information.

using System;
using System.Security.Cryptography;
using System.Text;

namespace Dtls.Crypto;

/// <summary>
/// Completes the TLS 1.3 / DTLS 1.3 key schedule (RFC 8446 section 7.1, RFC 9147) on top of
/// the lower-level <see cref="KeySchedule"/> primitives: it derives the early, handshake,
/// and master secrets, the directional traffic secrets, and computes/verifies the Finished
/// <c>verify_data</c> and the PSK binder (RFC 8446 section 4.2.11.2). All transcript inputs
/// are transcript-hash values (not raw messages).
/// </summary>
internal static class Dtls13KeySchedule
{
    private static readonly byte[] ExternalBinderLabel = Encoding.ASCII.GetBytes("ext binder");
    private static readonly byte[] ClientHandshakeTrafficLabel =
        Encoding.ASCII.GetBytes("c hs traffic");

    private static readonly byte[] ServerHandshakeTrafficLabel =
        Encoding.ASCII.GetBytes("s hs traffic");

    private static readonly byte[] ClientApplicationTrafficLabel =
        Encoding.ASCII.GetBytes("c ap traffic");

    private static readonly byte[] ServerApplicationTrafficLabel =
        Encoding.ASCII.GetBytes("s ap traffic");

    private static readonly byte[] FinishedLabel = Encoding.ASCII.GetBytes("finished");

    private static readonly byte[] TrafficUpdateLabel = Encoding.ASCII.GetBytes("traffic upd");

    /// <summary>
    /// Early Secret = HKDF-Extract(0, PSK). An empty PSK yields the (EC)DHE-only baseline.
    /// </summary>
    public static byte[] EarlySecret(HashAlgorithmName hash, ReadOnlySpan<byte> presharedKey) =>
        KeySchedule.EarlySecret(hash, presharedKey);

    /// <summary>
    /// binder_key = Derive-Secret(Early Secret, "ext binder", "") for an external PSK.
    /// </summary>
    public static byte[] DeriveExternalBinderKey(
        HashAlgorithmName hash,
        ReadOnlySpan<byte> earlySecret)
    {
        Span<byte> emptyHash = stackalloc byte[Hkdf.HashLength(hash)];
        HashEmpty(hash, emptyHash);
        return KeySchedule.DeriveSecret(hash, earlySecret, ExternalBinderLabel, emptyHash);
    }

    /// <summary>
    /// Handshake Secret = HKDF-Extract(Derive-Secret(Early, "derived", ""), ECDHE).
    /// </summary>
    public static byte[] DeriveHandshakeSecret(
        HashAlgorithmName hash,
        ReadOnlySpan<byte> earlySecret,
        ReadOnlySpan<byte> ecdheSharedSecret) =>
        KeySchedule.DeriveNext(hash, earlySecret, ecdheSharedSecret);

    /// <summary>
    /// Master Secret = HKDF-Extract(Derive-Secret(Handshake, "derived", ""), 0).
    /// </summary>
    public static byte[] DeriveMasterSecret(
        HashAlgorithmName hash,
        ReadOnlySpan<byte> handshakeSecret) =>
        KeySchedule.DeriveNext(hash, handshakeSecret, ReadOnlySpan<byte>.Empty);

    /// <summary>
    /// client_handshake_traffic_secret = Derive-Secret(Handshake, "c hs traffic", H).
    /// </summary>
    public static byte[] DeriveClientHandshakeTrafficSecret(
        HashAlgorithmName hash,
        ReadOnlySpan<byte> handshakeSecret,
        ReadOnlySpan<byte> transcriptHash) =>
        KeySchedule.DeriveSecret(
            hash,
            handshakeSecret,
            ClientHandshakeTrafficLabel,
            transcriptHash);

    /// <summary>
    /// server_handshake_traffic_secret = Derive-Secret(Handshake, "s hs traffic", H).
    /// </summary>
    public static byte[] DeriveServerHandshakeTrafficSecret(
        HashAlgorithmName hash,
        ReadOnlySpan<byte> handshakeSecret,
        ReadOnlySpan<byte> transcriptHash) =>
        KeySchedule.DeriveSecret(
            hash,
            handshakeSecret,
            ServerHandshakeTrafficLabel,
            transcriptHash);

    /// <summary>
    /// client_application_traffic_secret_0 = Derive-Secret(Master, "c ap traffic", H).
    /// </summary>
    public static byte[] DeriveClientApplicationTrafficSecret(
        HashAlgorithmName hash,
        ReadOnlySpan<byte> masterSecret,
        ReadOnlySpan<byte> transcriptHash) =>
        KeySchedule.DeriveSecret(hash, masterSecret, ClientApplicationTrafficLabel, transcriptHash);

    /// <summary>
    /// server_application_traffic_secret_0 = Derive-Secret(Master, "s ap traffic", H).
    /// </summary>
    public static byte[] DeriveServerApplicationTrafficSecret(
        HashAlgorithmName hash,
        ReadOnlySpan<byte> masterSecret,
        ReadOnlySpan<byte> transcriptHash) =>
        KeySchedule.DeriveSecret(hash, masterSecret, ServerApplicationTrafficLabel, transcriptHash);

    /// <summary>
    /// application_traffic_secret_N+1 = HKDF-Expand-Label(secret_N, "traffic upd", "",
    /// Hash.length) (RFC 8446 section 7.2). Advances the application traffic keys for KeyUpdate.
    /// </summary>
    public static byte[] NextApplicationTrafficSecret(
        HashAlgorithmName hash,
        ReadOnlySpan<byte> currentSecret) =>
        KeySchedule.ExpandLabel(
            hash,
            currentSecret,
            TrafficUpdateLabel,
            ReadOnlySpan<byte>.Empty,
            Hkdf.HashLength(hash));

    /// <summary>
    /// finished_key = HKDF-Expand-Label(BaseKey, "finished", "", Hash.length)
    /// (RFC 8446 section 4.4.4).
    /// </summary>
    public static byte[] DeriveFinishedKey(HashAlgorithmName hash, ReadOnlySpan<byte> baseKey) =>
        KeySchedule.ExpandLabel(
            hash,
            baseKey,
            FinishedLabel,
            ReadOnlySpan<byte>.Empty,
            Hkdf.HashLength(hash));

    /// <summary>
    /// Finished.verify_data = HMAC(Hash, finished_key, Transcript-Hash). The
    /// <paramref name="baseKey"/> is the relevant handshake traffic secret.
    /// </summary>
    public static byte[] ComputeVerifyData(
        HashAlgorithmName hash,
        ReadOnlySpan<byte> baseKey,
        ReadOnlySpan<byte> transcriptHash)
    {
        byte[] finishedKey = DeriveFinishedKey(hash, baseKey);
        try
        {
            return Hmac(hash, finishedKey, transcriptHash);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(finishedKey);
        }
    }

    /// <summary>
    /// Verifies a received Finished.verify_data in constant time against the value computed
    /// from <paramref name="baseKey"/> and <paramref name="transcriptHash"/>.
    /// </summary>
    public static bool VerifyFinished(
        HashAlgorithmName hash,
        ReadOnlySpan<byte> baseKey,
        ReadOnlySpan<byte> transcriptHash,
        ReadOnlySpan<byte> candidateVerifyData)
    {
        byte[] expected = ComputeVerifyData(hash, baseKey, transcriptHash);
        try
        {
            return CryptographicOperations.FixedTimeEquals(expected, candidateVerifyData);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(expected);
        }
    }

    /// <summary>
    /// Computes a PSK binder (RFC 8446 section 4.2.11.2): HMAC(Hash,
    /// finished_key(binder_key), Transcript-Hash(truncated ClientHello)). It is the same
    /// construction as the Finished message with the binder_key as the BaseKey.
    /// </summary>
    public static byte[] ComputeBinder(
        HashAlgorithmName hash,
        ReadOnlySpan<byte> binderKey,
        ReadOnlySpan<byte> truncatedTranscriptHash) =>
        ComputeVerifyData(hash, binderKey, truncatedTranscriptHash);

    /// <summary>
    /// Verifies a received PSK binder in constant time.
    /// </summary>
    public static bool VerifyBinder(
        HashAlgorithmName hash,
        ReadOnlySpan<byte> binderKey,
        ReadOnlySpan<byte> truncatedTranscriptHash,
        ReadOnlySpan<byte> candidateBinder) =>
        VerifyFinished(hash, binderKey, truncatedTranscriptHash, candidateBinder);

    private static byte[] Hmac(
        HashAlgorithmName hash,
        byte[] key,
        ReadOnlySpan<byte> message)
    {
        using IncrementalHash hmac = IncrementalHash.CreateHMAC(hash, key);
        hmac.AppendData(message.ToArray());
        return hmac.GetHashAndReset();
    }

    private static void HashEmpty(HashAlgorithmName hash, Span<byte> destination)
    {
        using IncrementalHash digest = IncrementalHash.CreateHash(hash);
        byte[] result = digest.GetHashAndReset();
        result.CopyTo(destination);
    }
}
