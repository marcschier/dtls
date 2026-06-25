// Copyright (c) marcschier. All rights reserved.
// Licensed under the MIT License. See LICENSE in the project root for license information.

#if NET8_0_OR_GREATER
using System;
using System.Runtime.InteropServices;
using System.Runtime.Versioning;

[assembly: DefaultDllImportSearchPaths(DllImportSearchPath.SafeDirectories)]

namespace Dtls.Interop.OpenSsl;

/// <summary>
/// P/Invoke surface for the OpenSSL libraries (<c>libssl</c> and <c>libcrypto</c>) exposed
/// on Linux. Only the subset required to drive a DTLS 1.2 handshake over a memory BIO pair
/// and protect application records is declared here. The library names are intentionally
/// unversioned ("libssl"/"libcrypto"); a <c>NativeLibrary</c> resolver registered by
/// <see cref="OpenSslLibraryResolver"/> maps them to the concrete versioned shared objects.
/// All marshalled types are blittable so the declarations remain Native AOT friendly.
/// </summary>
[SupportedOSPlatform("linux")]
internal static class OpenSslInterop
{
    /// <summary>The unversioned <c>libssl</c> import name resolved by the resolver.</summary>
    public const string LibSsl = "libssl";

    /// <summary>The unversioned <c>libcrypto</c> import name resolved by the resolver.</summary>
    public const string LibCrypto = "libcrypto";

    /// <summary>The on-the-wire DTLS 1.2 version constant (one's-complement encoded).</summary>
    public const long Dtls12Version = 0xFEFD;

    // SSL_ctrl / SSL_CTX_ctrl command codes.
    public const int SslCtrlSetMinProtoVersion = 123;
    public const int SslCtrlSetMaxProtoVersion = 124;
    public const int DtlsCtrlSetLinkMtu = 120;
    public const int SslCtrlOptions = 32;
    public const int DtlsCtrlGetTimeout = 73;
    public const int DtlsCtrlHandleTimeout = 74;

    /// <summary>Disables OpenSSL's path-MTU query, which a memory BIO cannot satisfy.</summary>
    public const long SslOpNoQueryMtu = 0x00001000;

    /// <summary>The link MTU advertised to OpenSSL for the memory-BIO DTLS transport.</summary>
    public const long LinkMtu = 1400;

    /// <summary>The ex-data class index for SSL objects (CRYPTO_EX_INDEX_SSL).</summary>
    public const int CryptoExIndexSsl = 0;

    // SSL_get_error return codes.
    public const int SslErrorNone = 0;
    public const int SslErrorSsl = 1;
    public const int SslErrorWantRead = 2;
    public const int SslErrorWantWrite = 3;
    public const int SslErrorWantX509Lookup = 4;
    public const int SslErrorSyscall = 5;
    public const int SslErrorZeroReturn = 6;
    public const int SslErrorWantConnect = 7;
    public const int SslErrorWantAccept = 8;

    [DllImport(LibSsl)]
    public static extern int OPENSSL_init_ssl(ulong opts, IntPtr settings);

    [DllImport(LibSsl)]
    public static extern IntPtr DTLS_method();

    [DllImport(LibSsl)]
    public static extern IntPtr SSL_CTX_new(IntPtr method);

    [DllImport(LibSsl)]
    public static extern void SSL_CTX_free(IntPtr ctx);

    [DllImport(LibSsl)]
    public static extern long SSL_CTX_ctrl(IntPtr ctx, int cmd, long larg, IntPtr parg);

    [DllImport(LibSsl)]
    public static extern int SSL_CTX_use_certificate(IntPtr ctx, IntPtr x509);

    [DllImport(LibSsl)]
    public static extern int SSL_CTX_use_PrivateKey(IntPtr ctx, IntPtr pkey);

    [DllImport(LibSsl)]
    public static extern int SSL_CTX_check_private_key(IntPtr ctx);

    [DllImport(LibSsl)]
    public static extern int SSL_CTX_set_cipher_list(IntPtr ctx, byte[] str);

    [DllImport(LibSsl)]
    public static extern void SSL_CTX_set_psk_server_callback(IntPtr ctx, IntPtr cb);

    [DllImport(LibSsl)]
    public static extern IntPtr SSL_new(IntPtr ctx);

    [DllImport(LibSsl)]
    public static extern void SSL_free(IntPtr ssl);

    [DllImport(LibSsl)]
    public static extern void SSL_set_bio(IntPtr ssl, IntPtr rbio, IntPtr wbio);

    [DllImport(LibSsl)]
    public static extern void SSL_set_connect_state(IntPtr ssl);

    [DllImport(LibSsl)]
    public static extern void SSL_set_accept_state(IntPtr ssl);

    [DllImport(LibSsl)]
    public static extern int SSL_do_handshake(IntPtr ssl);

    [DllImport(LibSsl)]
    public static extern int SSL_read(IntPtr ssl, IntPtr buf, int num);

    [DllImport(LibSsl)]
    public static extern int SSL_write(IntPtr ssl, IntPtr buf, int num);

    [DllImport(LibSsl)]
    public static extern int SSL_shutdown(IntPtr ssl);

    [DllImport(LibSsl)]
    public static extern int SSL_get_error(IntPtr ssl, int ret);

    [DllImport(LibSsl)]
    public static extern long SSL_ctrl(IntPtr ssl, int cmd, long larg, IntPtr parg);

    [DllImport(LibSsl)]
    public static extern void SSL_set_psk_client_callback(IntPtr ssl, IntPtr cb);

    [DllImport(LibSsl)]
    public static extern int SSL_set_ex_data(IntPtr ssl, int idx, IntPtr data);

    [DllImport(LibSsl)]
    public static extern IntPtr SSL_get_ex_data(IntPtr ssl, int idx);

    [DllImport(LibSsl)]
    public static extern IntPtr SSL_get1_peer_certificate(IntPtr ssl);

    [DllImport(LibSsl)]
    public static extern IntPtr SSL_get_peer_certificate(IntPtr ssl);

    [DllImport(LibSsl)]
    public static extern int SSL_version(IntPtr ssl);

    [DllImport(LibCrypto)]
    public static extern IntPtr BIO_new(IntPtr type);

    [DllImport(LibCrypto)]
    public static extern IntPtr BIO_s_mem();

    [DllImport(LibCrypto)]
    public static extern void BIO_free_all(IntPtr b);

    [DllImport(LibCrypto)]
    public static extern int BIO_write(IntPtr b, IntPtr data, int len);

    [DllImport(LibCrypto)]
    public static extern int BIO_read(IntPtr b, IntPtr data, int len);

    [DllImport(LibCrypto)]
    public static extern UIntPtr BIO_ctrl_pending(IntPtr b);

    [DllImport(LibCrypto)]
    public static extern IntPtr d2i_X509(IntPtr px, ref IntPtr input, long len);

    [DllImport(LibCrypto)]
    public static extern void X509_free(IntPtr x);

    [DllImport(LibCrypto)]
    public static extern IntPtr d2i_AutoPrivateKey(IntPtr a, ref IntPtr pp, long length);

    [DllImport(LibCrypto)]
    public static extern void EVP_PKEY_free(IntPtr pkey);

    [DllImport(LibCrypto, EntryPoint = "i2d_X509")]
    public static extern int i2d_X509_length(IntPtr x, IntPtr output);

    [DllImport(LibCrypto)]
    public static extern int i2d_X509(IntPtr x, ref IntPtr output);

    [DllImport(LibCrypto)]
    public static extern UIntPtr ERR_get_error();

    [DllImport(LibCrypto)]
    public static extern void ERR_error_string_n(UIntPtr e, byte[] buf, UIntPtr len);

    [DllImport(LibCrypto)]
    public static extern int CRYPTO_get_ex_new_index(
        int classIndex,
        long argl,
        IntPtr argp,
        IntPtr newFunc,
        IntPtr dupFunc,
        IntPtr freeFunc);
}
#endif
