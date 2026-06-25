// Copyright (c) marcschier. All rights reserved.
// Licensed under the MIT License. See LICENSE in the project root for license information.

using System;
using System.Security.Cryptography;

namespace Dtls.Crypto;

/// <summary>
/// The derived per-direction AEAD record keys for a DTLS 1.2 connection: the client and server
/// write keys and 4-byte salts split from the TLS 1.2 key_block (RFC 5246 section 6.3). For AEAD
/// suites there are no MAC keys.
/// </summary>
internal readonly struct Dtls12KeyBlock
{
    public Dtls12KeyBlock(
        byte[] clientWriteKey,
        byte[] serverWriteKey,
        byte[] clientWriteSalt,
        byte[] serverWriteSalt)
    {
        ClientWriteKey = clientWriteKey;
        ServerWriteKey = serverWriteKey;
        ClientWriteSalt = clientWriteSalt;
        ServerWriteSalt = serverWriteSalt;
    }

    public byte[] ClientWriteKey { get; }

    public byte[] ServerWriteKey { get; }

    public byte[] ClientWriteSalt { get; }

    public byte[] ServerWriteSalt { get; }

    /// <summary>Zeroes the key material.</summary>
    public void Clear()
    {
        CryptographicOperations.ZeroMemory(ClientWriteKey);
        CryptographicOperations.ZeroMemory(ServerWriteKey);
        CryptographicOperations.ZeroMemory(ClientWriteSalt);
        CryptographicOperations.ZeroMemory(ServerWriteSalt);
    }
}

/// <summary>
/// The TLS 1.2 key schedule (RFC 5246 section 8.1, RFC 5288, RFC 7627) built on
/// <see cref="Tls12Prf"/>: pre_master_secret assembly for the PSK key exchanges, master_secret
/// (standard and extended, RFC 7627), the AEAD key_block, and the Finished verify_data.
/// </summary>
internal static class Dtls12KeySchedule
{
    /// <summary>The TLS 1.2 master secret length, in bytes.</summary>
    public const int MasterSecretLength = 48;

    /// <summary>The Finished verify_data length, in bytes (RFC 5246 section 7.4.9).</summary>
    public const int VerifyDataLength = 12;

    /// <summary>
    /// master_secret = PRF(pre_master_secret, "master secret", client_random + server_random).
    /// </summary>
    public static byte[] MasterSecret(
        HashAlgorithmName hash,
        ReadOnlySpan<byte> preMasterSecret,
        ReadOnlySpan<byte> clientRandom,
        ReadOnlySpan<byte> serverRandom)
    {
        byte[] seed = Concat(clientRandom, serverRandom);
        byte[] master = Tls12Prf.Prf(
            hash, preMasterSecret, "master secret", seed, MasterSecretLength);
        CryptographicOperations.ZeroMemory(seed);
        return master;
    }

    /// <summary>
    /// extended master_secret = PRF(pre_master_secret, "extended master secret", session_hash),
    /// where session_hash is the handshake-message hash through ClientKeyExchange (RFC 7627).
    /// </summary>
    public static byte[] ExtendedMasterSecret(
        HashAlgorithmName hash,
        ReadOnlySpan<byte> preMasterSecret,
        ReadOnlySpan<byte> sessionHash)
    {
        return Tls12Prf.Prf(
            hash, preMasterSecret, "extended master secret", sessionHash, MasterSecretLength);
    }

    /// <summary>
    /// Derives the AEAD key_block (RFC 5246 section 6.3): for AEAD suites there are no MAC keys, so
    /// the block is client_write_key || server_write_key || client_write_salt || server_write_salt.
    /// </summary>
    public static Dtls12KeyBlock KeyBlock(
        HashAlgorithmName hash,
        ReadOnlySpan<byte> masterSecret,
        ReadOnlySpan<byte> serverRandom,
        ReadOnlySpan<byte> clientRandom,
        int keyLength)
    {
        int saltLength = Dtls12CipherSuite.SaltLength;
        int total = (2 * keyLength) + (2 * saltLength);

        byte[] seed = Concat(serverRandom, clientRandom);
        byte[] block = Tls12Prf.Prf(hash, masterSecret, "key expansion", seed, total);
        CryptographicOperations.ZeroMemory(seed);

        int offset = 0;
        byte[] clientWriteKey = Slice(block, ref offset, keyLength);
        byte[] serverWriteKey = Slice(block, ref offset, keyLength);
        byte[] clientWriteSalt = Slice(block, ref offset, saltLength);
        byte[] serverWriteSalt = Slice(block, ref offset, saltLength);

        CryptographicOperations.ZeroMemory(block);
        return new Dtls12KeyBlock(
            clientWriteKey, serverWriteKey, clientWriteSalt, serverWriteSalt);
    }

    /// <summary>
    /// verify_data = PRF(master_secret, finished_label, Hash(handshake_messages))[0..11]
    /// (RFC 5246 section 7.4.9). <paramref name="clientFinished"/> selects the
    /// "client finished" / "server finished" label.
    /// </summary>
    public static byte[] VerifyData(
        HashAlgorithmName hash,
        ReadOnlySpan<byte> masterSecret,
        ReadOnlySpan<byte> handshakeHash,
        bool clientFinished)
    {
        string label = clientFinished ? "client finished" : "server finished";
        return Tls12Prf.Prf(hash, masterSecret, label, handshakeHash, VerifyDataLength);
    }

    /// <summary>
    /// Assembles the ECDHE_PSK pre_master_secret (RFC 5489 section 2): struct {
    /// opaque other_secret = ecdhe_secret; opaque psk; }, each length-prefixed (uint16).
    /// </summary>
    public static byte[] EcdhePskPreMasterSecret(
        ReadOnlySpan<byte> ecdheSecret,
        ReadOnlySpan<byte> psk)
    {
        return PskPreMasterSecret(ecdheSecret, psk);
    }

    /// <summary>
    /// Assembles the plain-PSK pre_master_secret (RFC 4279 section 2): struct {
    /// opaque other_secret = zeros(psk.length); opaque psk; }, each length-prefixed (uint16).
    /// </summary>
    public static byte[] PlainPskPreMasterSecret(ReadOnlySpan<byte> psk)
    {
        Span<byte> zeros = psk.Length <= 256 ? stackalloc byte[psk.Length] : new byte[psk.Length];
        zeros.Clear();
        return PskPreMasterSecret(zeros, psk);
    }

    private static byte[] PskPreMasterSecret(ReadOnlySpan<byte> otherSecret, ReadOnlySpan<byte> psk)
    {
        if (otherSecret.Length > ushort.MaxValue || psk.Length > ushort.MaxValue)
        {
            throw new ArgumentException("PSK pre_master_secret component too large.");
        }

        byte[] result = new byte[2 + otherSecret.Length + 2 + psk.Length];
        Span<byte> span = result;
        span[0] = (byte)(otherSecret.Length >> 8);
        span[1] = (byte)otherSecret.Length;
        otherSecret.CopyTo(span.Slice(2));
        int offset = 2 + otherSecret.Length;
        span[offset] = (byte)(psk.Length >> 8);
        span[offset + 1] = (byte)psk.Length;
        psk.CopyTo(span.Slice(offset + 2));
        return result;
    }

    private static byte[] Concat(ReadOnlySpan<byte> a, ReadOnlySpan<byte> b)
    {
        byte[] result = new byte[a.Length + b.Length];
        a.CopyTo(result);
        b.CopyTo(result.AsSpan(a.Length));
        return result;
    }

    private static byte[] Slice(byte[] source, ref int offset, int length)
    {
        byte[] result = new byte[length];
        Array.Copy(source, offset, result, 0, length);
        offset += length;
        return result;
    }
}
