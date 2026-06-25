// Copyright (c) marcschier. All rights reserved.
// Licensed under the MIT License. See LICENSE in the project root for license information.

#if NET8_0_OR_GREATER
using System;
using System.Buffers;
using System.Collections.Generic;
using System.Runtime.InteropServices;
using System.Runtime.Versioning;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using Dtls.Transport;
using static Dtls.Interop.SecureTransport.SecureTransportInterop;

namespace Dtls.Interop.SecureTransport;

/// <summary>
/// A DTLS 1.2 connection established and protected by Apple's Secure Transport on macOS. The
/// handshake and record protection are delegated entirely to <c>Security.framework</c>; this
/// type only shuttles datagrams between the application's <see cref="IDatagramTransport"/> and
/// the <c>SSLContextRef</c> through a pair of read/write I/O callbacks. The read callback is
/// fed inbound datagrams and the write callback queues outbound records that are then flushed
/// as datagrams. Secure Transport is deprecated by Apple; a Network.framework backend is
/// tracked as future work.
/// </summary>
[SupportedOSPlatform("macos")]
internal sealed class SecureTransportDtlsConnection : DtlsConnection
{
    private readonly IDatagramTransport _transport;
    private readonly bool _isClient;
    private readonly int _maxDatagramSize;
    private readonly List<byte[]> _outbound = new();

    private IntPtr _ssl;
    private GCHandle _self;

    private byte[]? _inbound;
    private int _inboundOffset;
    private int _inboundLength;

    private DtlsRemoteCertificateValidation? _remoteValidation;
    private IntPtr _identityArray;
    private byte[]? _pfxPassword;

    private bool _peerClosed;
    private bool _closeSent;
    private bool _disposed;
    private DtlsProtocolVersion _negotiatedVersion = DtlsProtocolVersion.Dtls12;

    private SecureTransportDtlsConnection(IDatagramTransport transport, bool isClient)
    {
        _transport = transport;
        _isClient = isClient;
        _maxDatagramSize = transport.MaxDatagramSize;
    }

    /// <summary>Releases the unmanaged Secure Transport handles if disposal was missed.</summary>
    ~SecureTransportDtlsConnection()
    {
        Dispose(false);
    }

    /// <inheritdoc />
    public override DtlsProtocolVersion NegotiatedVersion => _negotiatedVersion;

    private void CaptureNegotiatedVersion()
    {
        if (SSLGetNegotiatedProtocolVersion(_ssl, out int protocol) == 0)
        {
            _negotiatedVersion = protocol switch
            {
                KDtlsProtocol12 => DtlsProtocolVersion.Dtls12,
                KDtlsProtocol1 => DtlsProtocolVersion.Dtls10,
                _ => DtlsProtocolVersion.Dtls12,
            };
        }
    }

    /// <summary>Performs a Secure Transport DTLS 1.2 client handshake.</summary>
    public static async Task<DtlsConnection> ConnectAsync(
        IDatagramTransport transport,
        DtlsClientOptions options,
        CancellationToken cancellationToken)
    {
        // CA2000: the connection is disposed on every failure path in the finally block and
        // ownership transfers to the caller on success.
#pragma warning disable CA2000
        SecureTransportDtlsConnection connection = new(transport, isClient: true);
#pragma warning restore CA2000
        bool established = false;
        CancellationTokenSource? timeout = StartTimeout(
            options, cancellationToken, out CancellationToken token);
        try
        {
            connection.SetupClient(options);
            await connection.DriveHandshakeAsync(ReadOnlyMemory<byte>.Empty, token)
                .ConfigureAwait(false);
            connection.CaptureNegotiatedVersion();
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

    /// <summary>Performs a Secure Transport DTLS 1.2 server handshake.</summary>
    public static async Task<DtlsConnection> AcceptAsync(
        IDatagramTransport transport,
        DtlsServerOptions options,
        ReadOnlyMemory<byte> initialDatagram,
        CancellationToken cancellationToken)
    {
        // CA2000: the connection is disposed on every failure path in the finally block and
        // ownership transfers to the caller on success.
#pragma warning disable CA2000
        SecureTransportDtlsConnection connection = new(transport, isClient: false);
#pragma warning restore CA2000
        bool established = false;
        CancellationTokenSource? timeout = StartTimeout(
            options, cancellationToken, out CancellationToken token);
        try
        {
            connection.SetupServer(options);
            await connection.DriveHandshakeAsync(initialDatagram, token).ConfigureAwait(false);
            connection.CaptureNegotiatedVersion();
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

        int ret = WritePlaintext(data.Span, out _);
        if (ret != NoErr)
        {
            throw Failure("SSLWrite", ret);
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

                int ret = ReadPlaintext(buffer.Span, out int processed);
                if (processed > 0 && (ret == NoErr || ret == ErrSSLWouldBlock))
                {
                    return processed;
                }

                if (ret == ErrSSLClosedGraceful || ret == ErrSSLClosedAbort)
                {
                    _peerClosed = true;
                    return 0;
                }

                if (ret == ErrSSLWouldBlock)
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

                    SetInbound(datagram.AsSpan(0, received));
                    continue;
                }

                throw Failure("SSLRead", ret);
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
        _ = SSLClose(_ssl);
        await DrainOutgoingAsync(cancellationToken).ConfigureAwait(false);
    }

    /// <summary>Read I/O callback: copies queued inbound bytes into Secure Transport.</summary>
    internal int HandleRead(IntPtr data, IntPtr dataLength)
    {
        int requested = (int)Marshal.ReadIntPtr(dataLength);
        int available = _inboundLength - _inboundOffset;
        int toCopy = requested < available ? requested : available;
        if (toCopy > 0 && _inbound is not null)
        {
            Marshal.Copy(_inbound, _inboundOffset, data, toCopy);
            _inboundOffset += toCopy;
        }

        Marshal.WriteIntPtr(dataLength, (IntPtr)toCopy);
        return toCopy == requested ? NoErr : ErrSSLWouldBlock;
    }

    /// <summary>Write I/O callback: enqueues one outbound datagram from Secure Transport.</summary>
    internal int HandleWrite(IntPtr data, IntPtr dataLength)
    {
        int count = (int)Marshal.ReadIntPtr(dataLength);
        if (count > 0)
        {
            byte[] datagram = new byte[count];
            Marshal.Copy(data, datagram, 0, count);
            _outbound.Add(datagram);
        }

        Marshal.WriteIntPtr(dataLength, (IntPtr)count);
        return NoErr;
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

    private void SetupClient(DtlsClientOptions options)
    {
        _remoteValidation = options.RemoteCertificateValidation;
        CreateContext(KSSLClientSide);

        // Break the handshake on server authentication so the managed validation callback can
        // inspect and pin the presented certificate before the handshake completes.
        Check(SSLSetSessionOption(_ssl, KSSLSessionOptionBreakOnServerAuth, 1),
            "SSLSetSessionOption");
    }

    private void SetupServer(DtlsServerOptions options)
    {
        CreateContext(KSSLServerSide);

        X509Certificate2 certificate = options.ServerCertificate
            ?? throw new DtlsException(
                "The Secure Transport DTLS 1.2 server backend requires a ServerCertificate.");
        LoadServerCertificate(certificate);
    }

    private void CreateContext(int protocolSide)
    {
        _ssl = SSLCreateContext(IntPtr.Zero, protocolSide, KSSLDatagramType);
        if (_ssl == IntPtr.Zero)
        {
            throw new DtlsException("Secure Transport SSLCreateContext returned null.");
        }

        // The deprecated SSLSetProtocolVersionMin/Max and SSLSetProtocolVersionEnabled APIs
        // reject DTLS 1.2 on recent macOS (errSSLBadConfiguration / OSStatus -909), so the
        // context uses Secure Transport's default datagram protocol — DTLS 1.0. The actual
        // negotiated version is read back after the handshake and surfaced via NegotiatedVersion.

        Check(SSLSetIOFuncs(_ssl, ReadCallback, WriteCallback), "SSLSetIOFuncs");

        _self = GCHandle.Alloc(this);
        Check(SSLSetConnection(_ssl, GCHandle.ToIntPtr(_self)), "SSLSetConnection");
    }

    private unsafe void LoadServerCertificate(X509Certificate2 certificate)
    {
        string password = Convert.ToBase64String(RandomNumberGenerator.GetBytes(24));
        byte[] pfx = certificate.Export(X509ContentType.Pfx, password);
        _pfxPassword = Encoding.UTF8.GetBytes(password + "\0");

        IntPtr pfxData = IntPtr.Zero;
        IntPtr passwordString = IntPtr.Zero;
        IntPtr options = IntPtr.Zero;
        IntPtr items = IntPtr.Zero;
        try
        {
            fixed (byte* p = pfx)
            {
                pfxData = CFDataCreate(IntPtr.Zero, (IntPtr)p, (IntPtr)pfx.Length);
            }

            if (pfxData == IntPtr.Zero)
            {
                throw new DtlsException("Secure Transport CFDataCreate(pfx) returned null.");
            }

            passwordString = CFStringCreateWithCString(
                IntPtr.Zero, _pfxPassword, KCFStringEncodingUtf8);
            if (passwordString == IntPtr.Zero)
            {
                throw new DtlsException(
                    "Secure Transport CFStringCreateWithCString returned null.");
            }

            IntPtr[] keys = { SecImportExportPassphrase };
            IntPtr[] values = { passwordString };
            options = CFDictionaryCreate(
                IntPtr.Zero,
                keys,
                values,
                (IntPtr)1,
                CFTypeDictionaryKeyCallBacks,
                CFTypeDictionaryValueCallBacks);
            if (options == IntPtr.Zero)
            {
                throw new DtlsException("Secure Transport CFDictionaryCreate returned null.");
            }

            int rc = SecPKCS12Import(pfxData, options, out items);
            if (rc != NoErr)
            {
                throw Failure("SecPKCS12Import", rc);
            }

            if (items == IntPtr.Zero || (long)CFArrayGetCount(items) <= 0)
            {
                throw new DtlsException("Secure Transport SecPKCS12Import produced no items.");
            }

            IntPtr item0 = CFArrayGetValueAtIndex(items, IntPtr.Zero);
            IntPtr identity = CFDictionaryGetValue(item0, SecImportItemIdentity);
            if (identity == IntPtr.Zero)
            {
                throw new DtlsException(
                    "Secure Transport PKCS#12 import produced no identity.");
            }

            IntPtr[] certValues = { identity };
            _identityArray = CFArrayCreate(
                IntPtr.Zero, certValues, (IntPtr)1, CFTypeArrayCallBacks);
            if (_identityArray == IntPtr.Zero)
            {
                throw new DtlsException(
                    "Secure Transport CFArrayCreate(identity) returned null.");
            }

            Check(SSLSetCertificate(_ssl, _identityArray), "SSLSetCertificate");
        }
        finally
        {
            if (items != IntPtr.Zero)
            {
                CFRelease(items);
            }

            if (options != IntPtr.Zero)
            {
                CFRelease(options);
            }

            if (passwordString != IntPtr.Zero)
            {
                CFRelease(passwordString);
            }

            if (pfxData != IntPtr.Zero)
            {
                CFRelease(pfxData);
            }

            CryptographicOperations.ZeroMemory(pfx);
        }
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
                SetInbound(initialDatagram.Span);
            }

            while (true)
            {
                cancellationToken.ThrowIfCancellationRequested();

                int ret = SSLHandshake(_ssl);
                await DrainOutgoingAsync(cancellationToken).ConfigureAwait(false);

                if (ret == NoErr)
                {
                    return;
                }

                if (ret == ErrSSLWouldBlock)
                {
                    int received = await _transport
                        .ReceiveAsync(datagram, cancellationToken)
                        .ConfigureAwait(false);
                    if (received == 0)
                    {
                        throw new DtlsException(
                            "The peer closed the connection during the DTLS handshake.");
                    }

                    SetInbound(datagram.AsSpan(0, received));
                    continue;
                }

                if (ret == ErrSSLServerAuthCompleted)
                {
                    ValidatePeerCertificate();
                    continue;
                }

                Debug($"SSLHandshake failed with OSStatus {ret}");
                throw Failure("SSLHandshake", ret);
            }
        }
        finally
        {
            ArrayPool<byte>.Shared.Return(datagram);
        }
    }

    private void ValidatePeerCertificate()
    {
        int rc = SSLCopyPeerTrust(_ssl, out IntPtr trust);
        if (rc != NoErr || trust == IntPtr.Zero)
        {
            if (_remoteValidation is not null)
            {
                throw Failure("SSLCopyPeerTrust", rc);
            }

            return;
        }

        IntPtr certData = IntPtr.Zero;
        try
        {
            IntPtr cert = SecTrustGetCertificateAtIndex(trust, IntPtr.Zero);
            if (cert == IntPtr.Zero)
            {
                if (_remoteValidation is not null)
                {
                    throw new DtlsException("The server did not present a certificate.");
                }

                return;
            }

            certData = SecCertificateCopyData(cert);
            if (certData == IntPtr.Zero)
            {
                throw new DtlsException(
                    "Secure Transport SecCertificateCopyData returned null.");
            }

            byte[] der = CopyCFData(certData);
            using X509Certificate2 certificate = LoadCertificate(der);
            if (_remoteValidation is { } validate && !validate(certificate, null, true))
            {
                throw new DtlsException(
                    "The server certificate was rejected by the validation callback.");
            }
        }
        finally
        {
            if (certData != IntPtr.Zero)
            {
                CFRelease(certData);
            }

            CFRelease(trust);
        }
    }

    private static byte[] CopyCFData(IntPtr data)
    {
        IntPtr bytes = CFDataGetBytePtr(data);
        int length = (int)CFDataGetLength(data);
        byte[] result = new byte[length];
        if (length > 0)
        {
            Marshal.Copy(bytes, result, 0, length);
        }

        return result;
    }

    private static X509Certificate2 LoadCertificate(byte[] der)
    {
#if NET9_0_OR_GREATER
        return X509CertificateLoader.LoadCertificate(der);
#else
        return new X509Certificate2(der);
#endif
    }

    private void SetInbound(ReadOnlySpan<byte> data)
    {
        if (_inbound is null || _inbound.Length < data.Length)
        {
            _inbound = new byte[data.Length];
        }

        data.CopyTo(_inbound);
        _inboundOffset = 0;
        _inboundLength = data.Length;
    }

    private async Task DrainOutgoingAsync(CancellationToken cancellationToken)
    {
        while (_outbound.Count > 0)
        {
            byte[] datagram = _outbound[0];
            _outbound.RemoveAt(0);
            await _transport.SendAsync(datagram, cancellationToken).ConfigureAwait(false);
        }
    }

    private unsafe int WritePlaintext(ReadOnlySpan<byte> data, out int processed)
    {
        fixed (byte* p = data)
        {
            int ret = SSLWrite(_ssl, (IntPtr)p, (UIntPtr)data.Length, out UIntPtr written);
            processed = (int)written;
            return ret;
        }
    }

    private unsafe int ReadPlaintext(Span<byte> destination, out int processed)
    {
        fixed (byte* p = destination)
        {
            int ret = SSLRead(_ssl, (IntPtr)p, (UIntPtr)destination.Length, out UIntPtr read);
            processed = (int)read;
            return ret;
        }
    }

    private static void Check(int status, string operation)
    {
        if (status != NoErr)
        {
            throw Failure(operation, status);
        }
    }

    private static DtlsException Failure(string operation, int status)
    {
        return new DtlsException($"Secure Transport {operation} failed: OSStatus {status}.");
    }

    private static void Debug(string message)
    {
        if (Environment.GetEnvironmentVariable("DTLS_DEBUG") is not null)
        {
            Console.Error.WriteLine("[SecureTransport] " + message);
        }
    }

    private void ThrowIfDisposed()
    {
        if (_disposed)
        {
            throw new ObjectDisposedException(nameof(SecureTransportDtlsConnection));
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

        if (_identityArray != IntPtr.Zero)
        {
            CFRelease(_identityArray);
            _identityArray = IntPtr.Zero;
        }

        if (_ssl != IntPtr.Zero)
        {
            CFRelease(_ssl);
            _ssl = IntPtr.Zero;
        }

        if (_self.IsAllocated)
        {
            _self.Free();
        }

        if (_pfxPassword is not null)
        {
            CryptographicOperations.ZeroMemory(_pfxPassword);
            _pfxPassword = null;
        }
    }
}
#endif
