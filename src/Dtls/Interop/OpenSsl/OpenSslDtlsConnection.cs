// Copyright (c) marcschier. All rights reserved.
// Licensed under the MIT License. See LICENSE in the project root for license information.

#if NET8_0_OR_GREATER
using System;
using System.Buffers;
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;
using System.Runtime.Versioning;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using Dtls.Transport;
using static Dtls.Interop.OpenSsl.OpenSslInterop;

namespace Dtls.Interop.OpenSsl;

/// <summary>
/// A DTLS 1.2 connection established and protected by OpenSSL on Linux. The handshake and
/// record protection are delegated entirely to <c>libssl</c>; this type only shuttles
/// datagrams between the application's <see cref="IDatagramTransport"/> and a pair of memory
/// BIOs that OpenSSL reads from and writes to. The read BIO is fed inbound datagrams and the
/// write BIO is drained and flushed as outbound datagrams.
/// </summary>
[SupportedOSPlatform("linux")]
internal sealed class OpenSslDtlsConnection : DtlsConnection
{
    private static readonly byte[] PskCipherList =
        Encoding.ASCII.GetBytes("PSK-AES128-GCM-SHA256:PSK-AES256-GCM-SHA384\0");

    private static readonly TimeSpan RetransmitPollInterval = TimeSpan.FromMilliseconds(500);

    private static readonly object PskIndexLock = new();
    private static int _pskExIndex;
    private static bool _pskExInitialized;
    private static int _libraryInitialized;

    private readonly IDatagramTransport _transport;
    private readonly bool _isClient;
    private readonly int _maxDatagramSize;

    private IntPtr _ctx;
    private IntPtr _ssl;
    private IntPtr _rbio;
    private IntPtr _wbio;
    private GCHandle _pskHandle;
    private bool _usePsk;
    private bool _peerClosed;
    private bool _closeSent;
    private bool _disposed;

    private OpenSslDtlsConnection(IDatagramTransport transport, bool isClient)
    {
        _transport = transport;
        _isClient = isClient;
        _maxDatagramSize = transport.MaxDatagramSize;
    }

    /// <summary>Releases the unmanaged OpenSSL handles if disposal was missed.</summary>
    ~OpenSslDtlsConnection()
    {
        Dispose(false);
    }

    /// <inheritdoc />
    public override DtlsProtocolVersion NegotiatedVersion => DtlsProtocolVersion.Dtls12;

    /// <summary>Performs an OpenSSL DTLS 1.2 client handshake and returns the connection.</summary>
    public static async Task<DtlsConnection> ConnectAsync(
        IDatagramTransport transport,
        DtlsClientOptions options,
        CancellationToken cancellationToken)
    {
        EnsureInitialized();

        // CA2000: the connection is disposed on every failure path in the finally block and
        // ownership transfers to the caller on success.
#pragma warning disable CA2000
        OpenSslDtlsConnection connection = new(transport, isClient: true);
#pragma warning restore CA2000
        bool established = false;
        CancellationTokenSource? timeout = StartTimeout(
            options, cancellationToken, out CancellationToken token);
        try
        {
            connection.SetupClient(options);
            await connection.DriveHandshakeAsync(ReadOnlyMemory<byte>.Empty, token)
                .ConfigureAwait(false);
            connection.ValidateServerCertificate(options);
            established = true;
            return connection;
        }
        catch (OperationCanceledException) when (
            timeout is { IsCancellationRequested: true }
            && !cancellationToken.IsCancellationRequested)
        {
            throw new DtlsException("The DTLS handshake timed out.");
        }
        finally
        {
            timeout?.Dispose();
            if (!established)
            {
                connection.Dispose();
            }
        }
    }

    /// <summary>Performs an OpenSSL DTLS 1.2 server handshake and returns the connection.</summary>
    public static async Task<DtlsConnection> AcceptAsync(
        IDatagramTransport transport,
        DtlsServerOptions options,
        ReadOnlyMemory<byte> initialDatagram,
        CancellationToken cancellationToken)
    {
        EnsureInitialized();

        // CA2000: the connection is disposed on every failure path in the finally block and
        // ownership transfers to the caller on success.
#pragma warning disable CA2000
        OpenSslDtlsConnection connection = new(transport, isClient: false);
#pragma warning restore CA2000
        bool established = false;
        CancellationTokenSource? timeout = StartTimeout(
            options, cancellationToken, out CancellationToken token);
        try
        {
            connection.SetupServer(options);
            await connection.DriveHandshakeAsync(initialDatagram, token).ConfigureAwait(false);
            established = true;
            return connection;
        }
        catch (OperationCanceledException) when (
            timeout is { IsCancellationRequested: true }
            && !cancellationToken.IsCancellationRequested)
        {
            throw new DtlsException("The DTLS handshake timed out.");
        }
        finally
        {
            timeout?.Dispose();
            if (!established)
            {
                connection.Dispose();
            }
        }
    }

    /// <inheritdoc />
    public override async ValueTask SendAsync(
        ReadOnlyMemory<byte> data,
        CancellationToken cancellationToken = default)
    {
        ThrowIfDisposed();

        int ret = WritePlaintext(data.Span);
        if (ret <= 0)
        {
            int error = SSL_get_error(_ssl, ret);
            throw new DtlsException(
                $"OpenSSL SSL_write failed ({DescribeError(error)}). {LastError()}");
        }

        await DrainOutgoingAsync(cancellationToken).ConfigureAwait(false);
    }

    /// <inheritdoc />
    public override async ValueTask<int> ReceiveAsync(
        Memory<byte> buffer,
        CancellationToken cancellationToken = default)
    {
        ThrowIfDisposed();

        if (_peerClosed)
        {
            return 0;
        }

        byte[] datagram = ArrayPool<byte>.Shared.Rent(_maxDatagramSize);
        try
        {
            while (true)
            {
                cancellationToken.ThrowIfCancellationRequested();

                int ret = ReadPlaintext(buffer.Span, out int error);
                if (ret > 0)
                {
                    return ret;
                }

                if (error == SslErrorZeroReturn)
                {
                    _peerClosed = true;
                    return 0;
                }

                if (error == SslErrorWantRead)
                {
                    await DrainOutgoingAsync(cancellationToken).ConfigureAwait(false);
                    int received = await _transport
                        .ReceiveAsync(datagram, cancellationToken)
                        .ConfigureAwait(false);
                    if (received == 0)
                    {
                        _peerClosed = true;
                        return 0;
                    }

                    WriteToReadBio(datagram.AsSpan(0, received));
                    continue;
                }

                if (error == SslErrorSyscall && ret == 0)
                {
                    _peerClosed = true;
                    return 0;
                }

                throw new DtlsException(
                    $"OpenSSL SSL_read failed ({DescribeError(error)}). {LastError()}");
            }
        }
        finally
        {
            ArrayPool<byte>.Shared.Return(datagram);
        }
    }

    /// <inheritdoc />
    public override async ValueTask CloseAsync(CancellationToken cancellationToken = default)
    {
        if (_disposed || _closeSent || _ssl == IntPtr.Zero)
        {
            return;
        }

        _closeSent = true;
        _ = SSL_shutdown(_ssl);
        await DrainOutgoingAsync(cancellationToken).ConfigureAwait(false);
    }

    private static CancellationTokenSource? StartTimeout(
        DtlsOptions options,
        CancellationToken cancellationToken,
        out CancellationToken effective)
    {
        if (options.HandshakeTimeout <= TimeSpan.Zero)
        {
            effective = cancellationToken;
            return null;
        }

        CancellationTokenSource cts =
            CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        cts.CancelAfter(options.HandshakeTimeout);
        effective = cts.Token;
        return cts;
    }

    private static void EnsureInitialized()
    {
        OpenSslLibraryResolver.Register();
        if (Interlocked.Exchange(ref _libraryInitialized, 1) == 0)
        {
            _ = OPENSSL_init_ssl(0, IntPtr.Zero);
        }
    }

    private static int GetPskExIndex()
    {
        if (Volatile.Read(ref _pskExInitialized))
        {
            return _pskExIndex;
        }

        lock (PskIndexLock)
        {
            if (!_pskExInitialized)
            {
                _pskExIndex = CRYPTO_get_ex_new_index(
                    CryptoExIndexSsl, 0, IntPtr.Zero, IntPtr.Zero, IntPtr.Zero, IntPtr.Zero);
                _pskExInitialized = true;
            }
        }

        return _pskExIndex;
    }

    private unsafe void SetupClient(DtlsClientOptions options)
    {
        CreateContext();
        _usePsk = options.PskCallback is not null;
        if (_usePsk)
        {
            SetCipherList(PskCipherList);
        }

        CreateSsl();

        if (_usePsk)
        {
            AttachPskContext(new OpenSslPskContext(options.PskCallback, null));
            SSL_set_psk_client_callback(
                _ssl,
                (IntPtr)(delegate* unmanaged[Cdecl]<
                    IntPtr, IntPtr, IntPtr, uint, IntPtr, uint, uint>)&ClientPskCallback);
        }

        SSL_set_connect_state(_ssl);
    }

    private unsafe void SetupServer(DtlsServerOptions options)
    {
        CreateContext();

        if (options.ServerCertificate is { } certificate)
        {
            LoadServerCertificate(certificate);
        }
        else if (options.PskCallback is not null)
        {
            _usePsk = true;
            SetCipherList(PskCipherList);
        }

        if (options.PskCallback is not null)
        {
            SSL_CTX_set_psk_server_callback(
                _ctx,
                (IntPtr)(delegate* unmanaged[Cdecl]<
                    IntPtr, IntPtr, IntPtr, uint, uint>)&ServerPskCallback);
        }

        CreateSsl();

        if (options.PskCallback is not null)
        {
            AttachPskContext(new OpenSslPskContext(null, options.PskCallback));
        }

        SSL_set_accept_state(_ssl);
    }

    private void CreateContext()
    {
        _ctx = SSL_CTX_new(DTLS_method());
        if (_ctx == IntPtr.Zero)
        {
            throw Failure("SSL_CTX_new");
        }

        _ = SSL_CTX_ctrl(_ctx, SslCtrlSetMinProtoVersion, Dtls12Version, IntPtr.Zero);
        _ = SSL_CTX_ctrl(_ctx, SslCtrlSetMaxProtoVersion, Dtls12Version, IntPtr.Zero);
    }

    private void CreateSsl()
    {
        _ssl = SSL_new(_ctx);
        if (_ssl == IntPtr.Zero)
        {
            throw Failure("SSL_new");
        }

        _rbio = BIO_new(BIO_s_mem());
        _wbio = BIO_new(BIO_s_mem());
        if (_rbio == IntPtr.Zero || _wbio == IntPtr.Zero)
        {
            throw Failure("BIO_new");
        }

        // SSL_set_bio transfers ownership of both BIOs to the SSL object; SSL_free releases
        // them, so they must not be freed separately once this call succeeds.
        SSL_set_bio(_ssl, _rbio, _wbio);

        _ = SSL_ctrl(_ssl, SslCtrlOptions, SslOpNoQueryMtu, IntPtr.Zero);
        _ = SSL_ctrl(_ssl, DtlsCtrlSetLinkMtu, LinkMtu, IntPtr.Zero);
    }

    private void SetCipherList(byte[] cipherList)
    {
        if (SSL_CTX_set_cipher_list(_ctx, cipherList) != 1)
        {
            throw Failure("SSL_CTX_set_cipher_list");
        }
    }

    private void AttachPskContext(OpenSslPskContext context)
    {
        _pskHandle = GCHandle.Alloc(context);
        _ = SSL_set_ex_data(_ssl, GetPskExIndex(), GCHandle.ToIntPtr(_pskHandle));
    }

    private unsafe void LoadServerCertificate(X509Certificate2 certificate)
    {
        byte[] certDer = certificate.RawData;
        IntPtr x509;
        fixed (byte* p = certDer)
        {
            IntPtr cursor = (IntPtr)p;
            x509 = d2i_X509(IntPtr.Zero, ref cursor, certDer.Length);
        }

        if (x509 == IntPtr.Zero)
        {
            throw Failure("d2i_X509");
        }

        try
        {
            if (SSL_CTX_use_certificate(_ctx, x509) != 1)
            {
                throw Failure("SSL_CTX_use_certificate");
            }
        }
        finally
        {
            X509_free(x509);
        }

        byte[] keyDer = ExportPrivateKey(certificate)
            ?? throw new DtlsException(
                "The server certificate has no exportable RSA or ECDSA private key.");
        try
        {
            IntPtr pkey;
            fixed (byte* p = keyDer)
            {
                IntPtr cursor = (IntPtr)p;
                pkey = d2i_AutoPrivateKey(IntPtr.Zero, ref cursor, keyDer.Length);
            }

            if (pkey == IntPtr.Zero)
            {
                throw Failure("d2i_AutoPrivateKey");
            }

            try
            {
                if (SSL_CTX_use_PrivateKey(_ctx, pkey) != 1)
                {
                    throw Failure("SSL_CTX_use_PrivateKey");
                }
            }
            finally
            {
                EVP_PKEY_free(pkey);
            }

            if (SSL_CTX_check_private_key(_ctx) != 1)
            {
                throw Failure("SSL_CTX_check_private_key");
            }
        }
        finally
        {
            CryptographicOperations.ZeroMemory(keyDer);
        }
    }

    private static byte[]? ExportPrivateKey(X509Certificate2 certificate)
    {
        using (RSA? rsa = certificate.GetRSAPrivateKey())
        {
            if (rsa is not null)
            {
                return rsa.ExportPkcs8PrivateKey();
            }
        }

        using (ECDsa? ecdsa = certificate.GetECDsaPrivateKey())
        {
            if (ecdsa is not null)
            {
                return ecdsa.ExportPkcs8PrivateKey();
            }
        }

        return null;
    }

    private async Task DriveHandshakeAsync(
        ReadOnlyMemory<byte> initialDatagram,
        CancellationToken cancellationToken)
    {
        byte[] datagram = ArrayPool<byte>.Shared.Rent(_maxDatagramSize);
        try
        {
            if (!_isClient && !initialDatagram.IsEmpty)
            {
                WriteToReadBio(initialDatagram.Span);
            }

            while (true)
            {
                cancellationToken.ThrowIfCancellationRequested();

                int ret = SSL_do_handshake(_ssl);
                await DrainOutgoingAsync(cancellationToken).ConfigureAwait(false);
                if (ret == 1)
                {
                    return;
                }

                int error = SSL_get_error(_ssl, ret);
                if (error == SslErrorWantRead)
                {
                    int received = await ReceiveHandshakeDatagramAsync(datagram, cancellationToken)
                        .ConfigureAwait(false);
                    if (received == 0)
                    {
                        throw new DtlsException(
                            "The peer closed the connection during the DTLS handshake.");
                    }

                    WriteToReadBio(datagram.AsSpan(0, received));
                }
                else if (error != SslErrorWantWrite)
                {
                    throw new DtlsException(
                        "The OpenSSL DTLS handshake failed "
                        + $"({DescribeError(error)}). {LastError()}");
                }
            }
        }
        finally
        {
            ArrayPool<byte>.Shared.Return(datagram);
        }
    }

    private async Task<int> ReceiveHandshakeDatagramAsync(
        byte[] datagram, CancellationToken cancellationToken)
    {
        // DTLS retransmission is timer-driven. OpenSSL parks the last flight; when no reply
        // arrives within its timeout we ask it to retransmit (DTLSv1_handle_timeout, which is
        // a no-op until OpenSSL's own timer is due) and flush whatever it re-queues. This keeps
        // the handshake alive over a lossy datagram transport such as UDP.
        while (true)
        {
            using CancellationTokenSource attempt =
                CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
            attempt.CancelAfter(RetransmitPollInterval);
            try
            {
                return await _transport.ReceiveAsync(datagram, attempt.Token)
                    .ConfigureAwait(false);
            }
            catch (OperationCanceledException) when (
                attempt.IsCancellationRequested && !cancellationToken.IsCancellationRequested)
            {
                _ = SSL_ctrl(_ssl, DtlsCtrlHandleTimeout, 0, IntPtr.Zero);
                await DrainOutgoingAsync(cancellationToken).ConfigureAwait(false);
            }
        }
    }

    private async Task DrainOutgoingAsync(CancellationToken cancellationToken)
    {
        while (true)
        {
            int pending = (int)BIO_ctrl_pending(_wbio);
            if (pending <= 0)
            {
                return;
            }

            byte[] buffer = ArrayPool<byte>.Shared.Rent(pending);
            try
            {
                int read = ReadFromWriteBio(buffer, pending);
                if (read <= 0)
                {
                    return;
                }

                await _transport.SendAsync(buffer.AsMemory(0, read), cancellationToken)
                    .ConfigureAwait(false);
            }
            finally
            {
                ArrayPool<byte>.Shared.Return(buffer);
            }
        }
    }

    private unsafe void WriteToReadBio(ReadOnlySpan<byte> data)
    {
        if (data.IsEmpty)
        {
            return;
        }

        fixed (byte* p = data)
        {
            int written = BIO_write(_rbio, (IntPtr)p, data.Length);
            if (written < data.Length)
            {
                throw Failure("BIO_write");
            }
        }
    }

    private unsafe int ReadFromWriteBio(byte[] buffer, int length)
    {
        fixed (byte* p = buffer)
        {
            return BIO_read(_wbio, (IntPtr)p, length);
        }
    }

    private unsafe int WritePlaintext(ReadOnlySpan<byte> data)
    {
        fixed (byte* p = data)
        {
            return SSL_write(_ssl, (IntPtr)p, data.Length);
        }
    }

    private unsafe int ReadPlaintext(Span<byte> destination, out int error)
    {
        int ret;
        fixed (byte* p = destination)
        {
            ret = SSL_read(_ssl, (IntPtr)p, destination.Length);
        }

        error = ret > 0 ? SslErrorNone : SSL_get_error(_ssl, ret);
        return ret;
    }

    private void ValidateServerCertificate(DtlsClientOptions options)
    {
        if (_usePsk)
        {
            return;
        }

        IntPtr peer = GetPeerCertificate();
        if (peer == IntPtr.Zero)
        {
            if (options.RemoteCertificateValidation is not null)
            {
                throw new DtlsException("The server did not present a certificate.");
            }

            return;
        }

        try
        {
            byte[] der = EncodeCertificate(peer);
#if NET9_0_OR_GREATER
            using X509Certificate2 certificate = X509CertificateLoader.LoadCertificate(der);
#else
            using X509Certificate2 certificate = new(der);
#endif
            if (options.RemoteCertificateValidation is { } validate
                && !validate(certificate, null, true))
            {
                throw new DtlsException(
                    "The server certificate was rejected by the validation callback.");
            }
        }
        finally
        {
            X509_free(peer);
        }
    }

    private IntPtr GetPeerCertificate()
    {
        try
        {
            return SSL_get1_peer_certificate(_ssl);
        }
        catch (EntryPointNotFoundException)
        {
            return SSL_get_peer_certificate(_ssl);
        }
    }

    private static unsafe byte[] EncodeCertificate(IntPtr x509)
    {
        int length = i2d_X509_length(x509, IntPtr.Zero);
        if (length <= 0)
        {
            throw Failure("i2d_X509");
        }

        byte[] der = new byte[length];
        fixed (byte* p = der)
        {
            IntPtr cursor = (IntPtr)p;
            _ = i2d_X509(x509, ref cursor);
        }

        return der;
    }

    private static DtlsException Failure(string operation)
    {
        return new DtlsException($"OpenSSL {operation} failed. {LastError()}");
    }

    private static string LastError()
    {
        UIntPtr code = ERR_get_error();
        if (code == UIntPtr.Zero)
        {
            return "(no OpenSSL error queued)";
        }

        byte[] buffer = new byte[256];
        ERR_error_string_n(code, buffer, (UIntPtr)buffer.Length);
        int length = Array.IndexOf(buffer, (byte)0);
        if (length < 0)
        {
            length = buffer.Length;
        }

        return Encoding.ASCII.GetString(buffer, 0, length);
    }

    private static string DescribeError(int error)
    {
        return error switch
        {
            SslErrorNone => "SSL_ERROR_NONE",
            SslErrorSsl => "SSL_ERROR_SSL",
            SslErrorWantRead => "SSL_ERROR_WANT_READ",
            SslErrorWantWrite => "SSL_ERROR_WANT_WRITE",
            SslErrorWantX509Lookup => "SSL_ERROR_WANT_X509_LOOKUP",
            SslErrorSyscall => "SSL_ERROR_SYSCALL",
            SslErrorZeroReturn => "SSL_ERROR_ZERO_RETURN",
            SslErrorWantConnect => "SSL_ERROR_WANT_CONNECT",
            SslErrorWantAccept => "SSL_ERROR_WANT_ACCEPT",
            _ => $"SSL_ERROR({error})",
        };
    }

    [UnmanagedCallersOnly(CallConvs = new[] { typeof(CallConvCdecl) })]
    private static unsafe uint ClientPskCallback(
        IntPtr ssl,
        IntPtr hint,
        IntPtr identity,
        uint maxIdentity,
        IntPtr psk,
        uint maxPsk)
    {
        try
        {
            if (RecoverContext(ssl)?.ClientCallback is not { } callback)
            {
                return 0;
            }

            string? hintText = hint == IntPtr.Zero ? null : Marshal.PtrToStringAnsi(hint);
            PskCredential credential = callback(hintText);
            ReadOnlySpan<byte> id = credential.Identity.Span;
            ReadOnlySpan<byte> key = credential.Key.Span;
            if (key.Length == 0
                || key.Length > maxPsk
                || (long)id.Length + 1 > maxIdentity)
            {
                return 0;
            }

            Span<byte> identityBuffer = new((void*)identity, (int)maxIdentity);
            id.CopyTo(identityBuffer);
            identityBuffer[id.Length] = 0;
            key.CopyTo(new Span<byte>((void*)psk, (int)maxPsk));
            return (uint)key.Length;
        }
        catch
        {
            return 0;
        }
    }

    [UnmanagedCallersOnly(CallConvs = new[] { typeof(CallConvCdecl) })]
    private static unsafe uint ServerPskCallback(
        IntPtr ssl,
        IntPtr identity,
        IntPtr psk,
        uint maxPsk)
    {
        try
        {
            if (RecoverContext(ssl)?.ServerCallback is not { } callback)
            {
                return 0;
            }

            byte[] identityBytes = ReadCString(identity);
            ReadOnlyMemory<byte> key = callback(identityBytes);
            if (key.IsEmpty || key.Length > maxPsk)
            {
                return 0;
            }

            key.Span.CopyTo(new Span<byte>((void*)psk, (int)maxPsk));
            return (uint)key.Length;
        }
        catch
        {
            return 0;
        }
    }

    private static OpenSslPskContext? RecoverContext(IntPtr ssl)
    {
        IntPtr handle = SSL_get_ex_data(ssl, GetPskExIndex());
        if (handle == IntPtr.Zero)
        {
            return null;
        }

        return GCHandle.FromIntPtr(handle).Target as OpenSslPskContext;
    }

    private static unsafe byte[] ReadCString(IntPtr pointer)
    {
        if (pointer == IntPtr.Zero)
        {
            return Array.Empty<byte>();
        }

        byte* bytes = (byte*)pointer;
        int length = 0;
        while (bytes[length] != 0)
        {
            length++;
        }

        byte[] result = new byte[length];
        new ReadOnlySpan<byte>(bytes, length).CopyTo(result);
        return result;
    }

    private void ThrowIfDisposed()
    {
        if (_disposed)
        {
            throw new ObjectDisposedException(nameof(OpenSslDtlsConnection));
        }
    }

    /// <inheritdoc />
    protected override void Dispose(bool disposing)
    {
        if (_disposed)
        {
            return;
        }

        _disposed = true;

        if (_ssl != IntPtr.Zero)
        {
            // SSL_free also releases the read and write BIOs handed to SSL_set_bio.
            SSL_free(_ssl);
            _ssl = IntPtr.Zero;
            _rbio = IntPtr.Zero;
            _wbio = IntPtr.Zero;
        }
        else
        {
            if (_rbio != IntPtr.Zero)
            {
                BIO_free_all(_rbio);
                _rbio = IntPtr.Zero;
            }

            if (_wbio != IntPtr.Zero)
            {
                BIO_free_all(_wbio);
                _wbio = IntPtr.Zero;
            }
        }

        if (_ctx != IntPtr.Zero)
        {
            SSL_CTX_free(_ctx);
            _ctx = IntPtr.Zero;
        }

        if (_pskHandle.IsAllocated)
        {
            _pskHandle.Free();
        }
    }
}

/// <summary>
/// Carries the managed PSK callbacks for a single OpenSSL DTLS connection. A pinned
/// <see cref="GCHandle"/> to an instance is stored in the SSL object's ex-data so the
/// unmanaged PSK trampolines can recover and invoke the managed delegates.
/// </summary>
[SupportedOSPlatform("linux")]
internal sealed class OpenSslPskContext
{
    public OpenSslPskContext(
        DtlsPskClientCallback? clientCallback,
        DtlsPskServerCallback? serverCallback)
    {
        ClientCallback = clientCallback;
        ServerCallback = serverCallback;
    }

    public DtlsPskClientCallback? ClientCallback { get; }

    public DtlsPskServerCallback? ServerCallback { get; }
}
#endif
