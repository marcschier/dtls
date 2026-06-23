using System;
using System.Buffers;
using System.Runtime.InteropServices;
using System.Runtime.Versioning;
using System.Security.Cryptography.X509Certificates;
using System.Threading;
using System.Threading.Tasks;
using Dtls.Transport;
using static Dtls.Interop.Schannel.SchannelInterop;

namespace Dtls.Interop.Schannel;

/// <summary>
/// A DTLS 1.2 connection established and protected by the Windows Schannel SSP. The handshake
/// is driven entirely by SSPI (<c>InitializeSecurityContext</c>/<c>AcceptSecurityContext</c>
/// with the datagram request flags); this type only shuttles tokens over the datagram
/// transport. Application records are protected with <c>EncryptMessage</c>/<c>DecryptMessage</c>.
/// </summary>
[SupportedOSPlatform("windows")]
internal sealed class SchannelDtlsConnection : DtlsConnection
{
    private readonly IDatagramTransport _transport;
    private readonly bool _isClient;
    private readonly string? _targetName;
    private readonly int _requestFlags;
    private readonly int _maxDatagramSize;
    private readonly X509Certificate2? _serverCertificate;

    private SecurityHandle _credential;
    private SecurityHandle _context;
    private bool _credentialAcquired;
    private bool _hasContext;

    private uint _header;
    private uint _trailer;
    private uint _maxMessage;

    private bool _peerClosed;
    private bool _closeSent;
    private bool _disposed;

    private SchannelDtlsConnection(
        IDatagramTransport transport,
        bool isClient,
        string? targetName,
        X509Certificate2? serverCertificate)
    {
        _transport = transport;
        _isClient = isClient;
        _targetName = targetName;
        _serverCertificate = serverCertificate;
        _maxDatagramSize = transport.MaxDatagramSize;
        int shared = ReqDatagram | ReqConfidentiality | ReqReplayDetect
            | ReqSequenceDetect | ReqAllocateMemory;
        _requestFlags = isClient
            ? shared | IscReqExtendedError
            : shared | AscReqExtendedError;
    }

    /// <inheritdoc />
    public override DtlsProtocolVersion NegotiatedVersion => DtlsProtocolVersion.Dtls12;

    /// <summary>Performs a Schannel DTLS 1.2 client handshake and returns the connection.</summary>
    public static async Task<DtlsConnection> ConnectAsync(
        IDatagramTransport transport,
        DtlsClientOptions options,
        CancellationToken cancellationToken)
    {
        // CA2000: the connection is disposed in the finally block on any failure path and
        // ownership transfers to the caller on success.
#pragma warning disable CA2000
        SchannelDtlsConnection connection = new(
            transport, isClient: true, options.TargetHost ?? "localhost", null);
#pragma warning restore CA2000
        bool established = false;
        CancellationTokenSource? timeout = StartTimeout(
            options, cancellationToken, out CancellationToken token);
        try
        {
            connection.AcquireClientCredentials();
            await connection.DriveHandshakeAsync(ReadOnlyMemory<byte>.Empty, token)
                .ConfigureAwait(false);
            connection.QueryStreamSizes();
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

    /// <summary>Performs a Schannel DTLS 1.2 server handshake and returns the connection.</summary>
    public static async Task<DtlsConnection> AcceptAsync(
        IDatagramTransport transport,
        DtlsServerOptions options,
        ReadOnlyMemory<byte> initialDatagram,
        CancellationToken cancellationToken)
    {
        X509Certificate2 certificate = options.ServerCertificate
            ?? throw new DtlsException(
                "The Schannel DTLS 1.2 server backend requires a ServerCertificate.");

        // CA2000: the connection is disposed in the finally block on any failure path and
        // ownership transfers to the caller on success.
#pragma warning disable CA2000
        SchannelDtlsConnection connection = new(
            transport, isClient: false, null, certificate);
#pragma warning restore CA2000
        bool established = false;
        CancellationTokenSource? timeout = StartTimeout(
            options, cancellationToken, out CancellationToken token);
        try
        {
            connection.AcquireServerCredentials(certificate);
            await connection.DriveHandshakeAsync(initialDatagram, token).ConfigureAwait(false);
            connection.QueryStreamSizes();
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

        if ((uint)data.Length > _maxMessage)
        {
            throw new DtlsException(
                "The application datagram exceeds the maximum protected message size "
                + $"({_maxMessage} bytes).");
        }

        int total = (int)_header + data.Length + (int)_trailer;
        byte[] buffer = ArrayPool<byte>.Shared.Rent(total);
        try
        {
            data.Span.CopyTo(buffer.AsSpan((int)_header));
            int length = Encrypt(buffer, data.Length);
            await _transport.SendAsync(buffer.AsMemory(0, length), cancellationToken)
                .ConfigureAwait(false);
        }
        finally
        {
            ArrayPool<byte>.Shared.Return(buffer);
        }
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
                int received = await _transport.ReceiveAsync(datagram, cancellationToken)
                    .ConfigureAwait(false);
                if (received == 0)
                {
                    _peerClosed = true;
                    return 0;
                }

                int produced = Decrypt(
                    datagram, received, buffer.Span, out bool closed, out bool retry);
                if (closed)
                {
                    _peerClosed = true;
                    return 0;
                }

                if (retry)
                {
                    continue;
                }

                return produced;
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
        if (_disposed || _closeSent || !_hasContext)
        {
            return;
        }

        _closeSent = true;
        byte[]? token = BuildShutdownToken();
        if (token is not null)
        {
            await _transport.SendAsync(token, cancellationToken).ConfigureAwait(false);
        }
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

    private async Task DriveHandshakeAsync(
        ReadOnlyMemory<byte> initialDatagram,
        CancellationToken cancellationToken)
    {
        byte[] receiveBuffer = ArrayPool<byte>.Shared.Rent(_maxDatagramSize);
        try
        {
            int status;
            byte[]? token;
            if (_isClient)
            {
                status = RunStep(null, 0, out token);
            }
            else
            {
                byte[] first = initialDatagram.ToArray();
                status = RunStep(first, first.Length, out token);
            }

            if (token is not null)
            {
                await _transport.SendAsync(token, cancellationToken).ConfigureAwait(false);
            }

            while (status != SecEOk)
            {
                cancellationToken.ThrowIfCancellationRequested();

                if (status == SecIContinueNeeded || status == SecEIncompleteMessage)
                {
                    int received = await _transport
                        .ReceiveAsync(receiveBuffer, cancellationToken)
                        .ConfigureAwait(false);
                    if (received == 0)
                    {
                        throw new DtlsException(
                            "The peer closed the connection during the DTLS handshake.");
                    }

                    status = RunStep(receiveBuffer, received, out token);
                }
                else if (status == SecIMessageFragment)
                {
                    status = RunStep(null, 0, out token);
                }
                else
                {
                    throw new DtlsException(
                        $"The Schannel DTLS handshake failed (0x{status:X8}).");
                }

                if (token is not null)
                {
                    await _transport.SendAsync(token, cancellationToken).ConfigureAwait(false);
                }
            }
        }
        finally
        {
            ArrayPool<byte>.Shared.Return(receiveBuffer);
        }
    }

    private unsafe int RunStep(byte[]? input, int inputLength, out byte[]? outputToken)
    {
        outputToken = null;

        SecBuffer* outBuffers = stackalloc SecBuffer[1];
        outBuffers[0].CbBuffer = 0;
        outBuffers[0].BufferType = SecbufferToken;
        outBuffers[0].PvBuffer = IntPtr.Zero;

        SecBufferDesc outDesc;
        outDesc.UlVersion = SecbufferVersion;
        outDesc.CBuffers = 1;
        outDesc.PBuffers = (IntPtr)outBuffers;

        SecBuffer* inBuffers = stackalloc SecBuffer[2];
        SecBufferDesc inDesc;
        inDesc.UlVersion = SecbufferVersion;
        inDesc.CBuffers = 2;
        inDesc.PBuffers = (IntPtr)inBuffers;

        int status;
        fixed (byte* pInput = input)
        fixed (SecurityHandle* pContext = &_context)
        {
            IntPtr inputDesc = IntPtr.Zero;
            if (input is not null)
            {
                inBuffers[0].CbBuffer = (uint)inputLength;
                inBuffers[0].BufferType = SecbufferToken;
                inBuffers[0].PvBuffer = (IntPtr)pInput;
                inBuffers[1].CbBuffer = 0;
                inBuffers[1].BufferType = SecbufferExtra;
                inBuffers[1].PvBuffer = IntPtr.Zero;
                inputDesc = (IntPtr)(&inDesc);
            }

            IntPtr phContext = _hasContext ? (IntPtr)pContext : IntPtr.Zero;
            IntPtr phNewContext = (IntPtr)pContext;

            if (_isClient)
            {
                status = InitializeSecurityContext(
                    ref _credential,
                    phContext,
                    _targetName,
                    _requestFlags,
                    0,
                    SecurityNativeDrep,
                    inputDesc,
                    0,
                    phNewContext,
                    (IntPtr)(&outDesc),
                    out _,
                    out _);
            }
            else
            {
                status = AcceptSecurityContext(
                    ref _credential,
                    phContext,
                    inputDesc,
                    _requestFlags,
                    SecurityNativeDrep,
                    phNewContext,
                    (IntPtr)(&outDesc),
                    out _,
                    out _);
            }

            _hasContext = true;

            if (outBuffers[0].CbBuffer > 0 && outBuffers[0].PvBuffer != IntPtr.Zero)
            {
                outputToken = new byte[outBuffers[0].CbBuffer];
                Marshal.Copy(outBuffers[0].PvBuffer, outputToken, 0, outputToken.Length);
                _ = FreeContextBuffer(outBuffers[0].PvBuffer);
            }
        }

        return status;
    }

    private unsafe int Encrypt(byte[] buffer, int dataLength)
    {
        SecBuffer* buffers = stackalloc SecBuffer[4];
        fixed (byte* p = buffer)
        {
            buffers[0].CbBuffer = _header;
            buffers[0].BufferType = SecbufferStreamHeader;
            buffers[0].PvBuffer = (IntPtr)p;
            buffers[1].CbBuffer = (uint)dataLength;
            buffers[1].BufferType = SecbufferData;
            buffers[1].PvBuffer = (IntPtr)(p + _header);
            buffers[2].CbBuffer = _trailer;
            buffers[2].BufferType = SecbufferStreamTrailer;
            buffers[2].PvBuffer = (IntPtr)(p + _header + dataLength);
            buffers[3].CbBuffer = 0;
            buffers[3].BufferType = SecbufferEmpty;
            buffers[3].PvBuffer = IntPtr.Zero;

            SecBufferDesc desc;
            desc.UlVersion = SecbufferVersion;
            desc.CBuffers = 4;
            desc.PBuffers = (IntPtr)buffers;

            int status = EncryptMessage(ref _context, 0, (IntPtr)(&desc), 0);
            if (status != SecEOk)
            {
                throw new DtlsException($"Schannel EncryptMessage failed (0x{status:X8}).");
            }

            return (int)(buffers[0].CbBuffer + buffers[1].CbBuffer + buffers[2].CbBuffer);
        }
    }

    private unsafe int Decrypt(
        byte[] datagram,
        int length,
        Span<byte> destination,
        out bool closed,
        out bool retry)
    {
        closed = false;
        retry = false;

        SecBuffer* buffers = stackalloc SecBuffer[4];
        fixed (byte* p = datagram)
        {
            buffers[0].CbBuffer = (uint)length;
            buffers[0].BufferType = SecbufferData;
            buffers[0].PvBuffer = (IntPtr)p;
            for (int i = 1; i < 4; i++)
            {
                buffers[i].CbBuffer = 0;
                buffers[i].BufferType = SecbufferEmpty;
                buffers[i].PvBuffer = IntPtr.Zero;
            }

            SecBufferDesc desc;
            desc.UlVersion = SecbufferVersion;
            desc.CBuffers = 4;
            desc.PBuffers = (IntPtr)buffers;

            int status = DecryptMessage(ref _context, (IntPtr)(&desc), 0, out _);
            if (status == SecIContextExpired || status == SecEContextExpired)
            {
                closed = true;
                return 0;
            }

            if (status == SecEIncompleteMessage)
            {
                retry = true;
                return 0;
            }

            if (status != SecEOk && status != SecIRenegotiate)
            {
                throw new DtlsException($"Schannel DecryptMessage failed (0x{status:X8}).");
            }

            for (int i = 0; i < 4; i++)
            {
                if (buffers[i].BufferType != SecbufferData || buffers[i].CbBuffer == 0)
                {
                    continue;
                }

                int produced = (int)buffers[i].CbBuffer;
                if (produced > destination.Length)
                {
                    throw new DtlsException(
                        "The receive buffer is smaller than the decrypted datagram.");
                }

                int offset = (int)((byte*)buffers[i].PvBuffer - p);
                datagram.AsSpan(offset, produced).CopyTo(destination);
                return produced;
            }

            retry = true;
            return 0;
        }
    }

    private unsafe byte[]? BuildShutdownToken()
    {
        uint shutdown = SchannelShutdown;
        SecBuffer control;
        control.CbBuffer = sizeof(uint);
        control.BufferType = SecbufferToken;
        control.PvBuffer = (IntPtr)(&shutdown);

        SecBufferDesc controlDesc;
        controlDesc.UlVersion = SecbufferVersion;
        controlDesc.CBuffers = 1;
        controlDesc.PBuffers = (IntPtr)(&control);

        int status = ApplyControlToken(ref _context, (IntPtr)(&controlDesc));
        if (status != SecEOk)
        {
            return null;
        }

        RunStep(null, 0, out byte[]? token);
        return token;
    }

    private unsafe void AcquireClientCredentials()
    {
        SchannelCred cred = default;
        cred.DwVersion = SchannelCredVersion;
        cred.GrbitEnabledProtocols = SpProtDtls1_2Client;
        cred.DwFlags = SchCredManualCredValidation | SchCredNoDefaultCreds;

        SecurityHandle handle = default;
        int status = AcquireCredentialsHandle(
            null,
            UnifiedSecurityProtocolProvider,
            SecpkgCredOutbound,
            IntPtr.Zero,
            (IntPtr)(&cred),
            IntPtr.Zero,
            IntPtr.Zero,
            ref handle,
            out _);
        if (status != SecEOk)
        {
            throw new DtlsException(
                $"Schannel AcquireCredentialsHandle (client) failed (0x{status:X8}).");
        }

        _credential = handle;
        _credentialAcquired = true;
    }

    private unsafe void AcquireServerCredentials(X509Certificate2 certificate)
    {
        IntPtr certContext = certificate.Handle;
        SchannelCred cred = default;
        cred.DwVersion = SchannelCredVersion;
        cred.CCreds = 1;
        cred.PaCred = (IntPtr)(&certContext);
        cred.GrbitEnabledProtocols = SpProtDtls1_2Server;

        SecurityHandle handle = default;
        int status = AcquireCredentialsHandle(
            null,
            UnifiedSecurityProtocolProvider,
            SecpkgCredInbound,
            IntPtr.Zero,
            (IntPtr)(&cred),
            IntPtr.Zero,
            IntPtr.Zero,
            ref handle,
            out _);
        GC.KeepAlive(certificate);
        if (status != SecEOk)
        {
            throw new DtlsException(
                $"Schannel AcquireCredentialsHandle (server) failed (0x{status:X8}).");
        }

        _credential = handle;
        _credentialAcquired = true;
    }

    private unsafe void QueryStreamSizes()
    {
        SecPkgContextStreamSizes sizes = default;
        int status = QueryContextAttributes(
            ref _context, SecpkgAttrStreamSizes, (IntPtr)(&sizes));
        if (status != SecEOk)
        {
            throw new DtlsException(
                $"Schannel QueryContextAttributes(STREAM_SIZES) failed (0x{status:X8}).");
        }

        _header = sizes.CbHeader;
        _trailer = sizes.CbTrailer;
        _maxMessage = sizes.CbMaximumMessage;
    }

    private void ValidateServerCertificate(DtlsClientOptions options)
    {
        // CA2000: the certificate is disposed in the finally block below.
#pragma warning disable CA2000
        X509Certificate2? certificate = QueryRemoteCertificate();
#pragma warning restore CA2000
        if (certificate is null)
        {
            if (options.RemoteCertificateValidation is not null)
            {
                throw new DtlsException("The server did not present a certificate.");
            }

            return;
        }

        try
        {
            if (options.RemoteCertificateValidation is { } validate
                && !validate(certificate, null, true))
            {
                throw new DtlsException(
                    "The server certificate was rejected by the validation callback.");
            }
        }
        finally
        {
            certificate.Dispose();
        }
    }

    private unsafe X509Certificate2? QueryRemoteCertificate()
    {
        IntPtr certContext = IntPtr.Zero;
        int status = QueryContextAttributes(
            ref _context, SecpkgAttrRemoteCertContext, (IntPtr)(&certContext));
        if (status != SecEOk || certContext == IntPtr.Zero)
        {
            return null;
        }

        try
        {
#pragma warning disable CA2000 // Ownership is transferred to the caller of this method.
            return new X509Certificate2(certContext);
#pragma warning restore CA2000
        }
        finally
        {
            CertFreeCertificateContext(certContext);
        }
    }

    private void ThrowIfDisposed()
    {
        if (_disposed)
        {
            throw new ObjectDisposedException(nameof(SchannelDtlsConnection));
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

        if (_hasContext)
        {
            _ = DeleteSecurityContext(ref _context);
            _hasContext = false;
        }

        if (_credentialAcquired)
        {
            _ = FreeCredentialsHandle(ref _credential);
            _credentialAcquired = false;
        }

        GC.KeepAlive(_serverCertificate);
    }
}
