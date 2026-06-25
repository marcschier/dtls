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
using Dtls.Interop.SecureTransport;
using Dtls.Transport;
using static Dtls.Interop.Network.NetworkInterop;

namespace Dtls.Interop.Network;

/// <summary>
/// A DTLS 1.2 connection established and protected by Apple's <c>Network.framework</c> on macOS.
/// Network.framework owns its own UDP transport, so the handshake runs over a private loopback
/// socket and a <see cref="NetworkLoopbackRelay"/> shuttles the encrypted datagrams to and from the
/// application's <see cref="IDatagramTransport"/>. The asynchronous <c>nw_connection</c> /
/// <c>nw_listener</c> callbacks are Objective-C blocks created via <see cref="NwBlock"/>; their
/// invoke trampolines are <c>UnmanagedCallersOnly</c> statics that route back to the owning
/// instance through a captured <see cref="GCHandle"/>.
/// </summary>
[SupportedOSPlatform("macos")]
internal sealed class NetworkDtlsConnection : DtlsConnection
{
    private readonly IDatagramTransport _transport;
    private readonly bool _isClient;

    private GCHandle _self;
    private IntPtr _queue;
    private IntPtr _connection;
    private IntPtr _listener;
    private NetworkLoopbackRelay? _relay;

    private IntPtr _configureTlsBlock;
    private IntPtr _stateBlock;
    private IntPtr _listenerStateBlock;
    private IntPtr _newConnectionBlock;
    private IntPtr _verifyBlock;
    private IntPtr _receiveBlock;
    private IntPtr _sendBlock;

    private IntPtr _secIdentity;
    private IntPtr _importedItems;

    private DtlsRemoteCertificateValidation? _remoteValidation;

    private readonly TaskCompletionSource<bool> _ready =
        new(TaskCreationOptions.RunContinuationsAsynchronously);
    private readonly TaskCompletionSource<bool> _listenerReady =
        new(TaskCreationOptions.RunContinuationsAsynchronously);
    private readonly TaskCompletionSource<IntPtr> _newConnection =
        new(TaskCreationOptions.RunContinuationsAsynchronously);

    private readonly SemaphoreSlim _sendLock = new(1, 1);
    private readonly SemaphoreSlim _receiveLock = new(1, 1);
    private TaskCompletionSource<bool>? _pendingSend;
    private TaskCompletionSource<ReceiveOutcome>? _pendingReceive;

    private DtlsProtocolVersion _negotiatedVersion = DtlsProtocolVersion.Dtls12;
    private bool _peerClosed;
    private int _disposed;
    private int _teardownStarted;
    private int _pendingTerminal;
    private int _nativeFreed;

    private NetworkDtlsConnection(IDatagramTransport transport, bool isClient)
    {
        _transport = transport;
        _isClient = isClient;
    }

    /// <summary>Releases the unmanaged Network.framework handles if disposal was missed.</summary>
    ~NetworkDtlsConnection()
    {
        Dispose(false);
    }

    /// <inheritdoc />
    public override DtlsProtocolVersion NegotiatedVersion => _negotiatedVersion;

    private static int _available = -1;

    /// <summary>
    /// Whether Network.framework and its secure-UDP entry points can be resolved on this host.
    /// When <see langword="false"/>, the macOS backend falls back to Secure Transport (DTLS 1.0).
    /// </summary>
    public static bool IsAvailable
    {
        get
        {
            if (_available < 0)
            {
                _available = Probe() ? 1 : 0;
            }

            return _available == 1;
        }
    }

    private static bool Probe()
    {
        try
        {
            return NativeLibrary.TryLoad(NetworkInterop.Network, out IntPtr handle)
                && NativeLibrary.TryGetExport(
                    handle, "nw_parameters_create_secure_udp", out _);
        }
        catch (Exception)
        {
            return false;
        }
    }

    /// <summary>Performs a Network.framework DTLS 1.2 client handshake.</summary>
    public static async Task<DtlsConnection> ConnectAsync(
        IDatagramTransport transport,
        DtlsClientOptions options,
        CancellationToken cancellationToken)
    {
#pragma warning disable CA2000
        NetworkDtlsConnection connection = new(transport, isClient: true);
#pragma warning restore CA2000
        bool established = false;
        CancellationTokenSource timeout = LinkTimeout(
            options, cancellationToken, out CancellationToken token);
        try
        {
            connection._remoteValidation = options.RemoteCertificateValidation;
            connection.StartClient(transport);
            await connection._ready.Task.WaitAsync(token).ConfigureAwait(false);
            connection.CaptureNegotiatedVersion();
            established = true;
            return connection;
        }
        catch (OperationCanceledException) when (
            timeout.IsCancellationRequested && !cancellationToken.IsCancellationRequested)
        {
            throw new DtlsException("The DTLS handshake timed out.");
        }
        finally
        {
            timeout.Dispose();
            if (!established)
            {
                connection.Dispose();
            }
        }
    }

    /// <summary>Performs a Network.framework DTLS 1.2 server handshake.</summary>
    public static async Task<DtlsConnection> AcceptAsync(
        IDatagramTransport transport,
        DtlsServerOptions options,
        ReadOnlyMemory<byte> initialDatagram,
        CancellationToken cancellationToken)
    {
#pragma warning disable CA2000
        NetworkDtlsConnection connection = new(transport, isClient: false);
#pragma warning restore CA2000
        bool established = false;
        CancellationTokenSource timeout = LinkTimeout(
            options, cancellationToken, out CancellationToken token);
        try
        {
            X509Certificate2 certificate = options.ServerCertificate
                ?? throw new DtlsException(
                    "The Network.framework DTLS server backend requires a ServerCertificate.");
            await connection.StartServerAsync(transport, certificate, initialDatagram, token)
                .ConfigureAwait(false);
            await connection._ready.Task.WaitAsync(token).ConfigureAwait(false);
            connection.CaptureNegotiatedVersion();
            established = true;
            return connection;
        }
        catch (OperationCanceledException) when (
            timeout.IsCancellationRequested && !cancellationToken.IsCancellationRequested)
        {
            throw new DtlsException("The DTLS handshake timed out.");
        }
        finally
        {
            timeout.Dispose();
            if (!established)
            {
                connection.Dispose();
            }
        }
    }

    private unsafe void AllocateShared()
    {
        _self = GCHandle.Alloc(this);
        IntPtr context = GCHandle.ToIntPtr(_self);
        _queue = dispatch_queue_create("com.dtls.network", IntPtr.Zero);

        _configureTlsBlock = NwBlock.Create(
            (IntPtr)(delegate* unmanaged[Cdecl]<IntPtr, IntPtr, void>)&ConfigureTlsTrampoline,
            context);
        _stateBlock = NwBlock.Create(
            (IntPtr)(delegate* unmanaged[Cdecl]<IntPtr, int, IntPtr, void>)&StateTrampoline,
            context);
        _receiveBlock = NwBlock.Create(
            (IntPtr)(delegate* unmanaged[Cdecl]<IntPtr, IntPtr, IntPtr, byte, IntPtr, void>)
                &ReceiveTrampoline,
            context);
        _sendBlock = NwBlock.Create(
            (IntPtr)(delegate* unmanaged[Cdecl]<IntPtr, IntPtr, void>)&SendTrampoline,
            context);
    }

    private unsafe void StartClient(IDatagramTransport transport)
    {
        AllocateShared();
        _verifyBlock = NwBlock.Create(
            (IntPtr)(delegate* unmanaged[Cdecl]<IntPtr, IntPtr, IntPtr, IntPtr, void>)
                &VerifyTrampoline,
            GCHandle.ToIntPtr(_self));

        _relay = NetworkLoopbackRelay.Create(initialTarget: null);
        IntPtr endpoint = nw_endpoint_create_host("127.0.0.1", _relay.LocalPort.ToString());
        IntPtr parameters = nw_parameters_create_secure_udp(
            _configureTlsBlock, DefaultProtocolConfiguration);

        _connection = nw_connection_create(endpoint, parameters);
        nw_release(endpoint);
        nw_release(parameters);
        if (_connection == IntPtr.Zero)
        {
            throw new DtlsException("Network.framework nw_connection_create returned null.");
        }

        nw_connection_set_queue(_connection, _queue);
        nw_connection_set_state_changed_handler(_connection, _stateBlock);
        _relay.Start(transport, ReadOnlyMemory<byte>.Empty);
        nw_connection_start(_connection);
    }

    private unsafe void SetupServerListener(X509Certificate2 certificate)
    {
        AllocateShared();
        _listenerStateBlock = NwBlock.Create(
            (IntPtr)(delegate* unmanaged[Cdecl]<IntPtr, int, IntPtr, void>)&ListenerStateTrampoline,
            GCHandle.ToIntPtr(_self));
        _newConnectionBlock = NwBlock.Create(
            (IntPtr)(delegate* unmanaged[Cdecl]<IntPtr, IntPtr, void>)&NewConnectionTrampoline,
            GCHandle.ToIntPtr(_self));

        LoadServerIdentity(certificate);

        IntPtr parameters = nw_parameters_create_secure_udp(
            _configureTlsBlock, DefaultProtocolConfiguration);
        _listener = nw_listener_create(parameters);
        nw_release(parameters);
        if (_listener == IntPtr.Zero)
        {
            throw new DtlsException("Network.framework nw_listener_create returned null.");
        }

        nw_listener_set_queue(_listener, _queue);
        nw_listener_set_state_changed_handler(_listener, _listenerStateBlock);
        nw_listener_set_new_connection_handler(_listener, _newConnectionBlock);
        nw_listener_start(_listener);
    }

    private async Task StartServerAsync(
        IDatagramTransport transport,
        X509Certificate2 certificate,
        ReadOnlyMemory<byte> initialDatagram,
        CancellationToken token)
    {
        SetupServerListener(certificate);

        await _listenerReady.Task.WaitAsync(token).ConfigureAwait(false);
        int port = nw_listener_get_port(_listener);

        _relay = NetworkLoopbackRelay.Create(
            new System.Net.IPEndPoint(System.Net.IPAddress.Loopback, port));
        _relay.Start(transport, initialDatagram);

        IntPtr accepted = await _newConnection.Task.WaitAsync(token).ConfigureAwait(false);
        _connection = accepted;
        nw_connection_set_queue(_connection, _queue);
        nw_connection_set_state_changed_handler(_connection, _stateBlock);
        nw_connection_start(_connection);
    }

    /// <inheritdoc />
    public override async ValueTask SendAsync(
        ReadOnlyMemory<byte> data,
        CancellationToken cancellationToken = default)
    {
        ThrowIfDisposed();
        await _sendLock.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            IntPtr content = CreateDispatchData(data.Span);
            TaskCompletionSource<bool> pending =
                new(TaskCreationOptions.RunContinuationsAsynchronously);
            _pendingSend = pending;
            nw_connection_send(_connection, content, DefaultMessageContext, 1, _sendBlock);
            if (content != IntPtr.Zero)
            {
                dispatch_release(content);
            }

            await pending.Task.WaitAsync(cancellationToken).ConfigureAwait(false);
        }
        finally
        {
            _pendingSend = null;
            _sendLock.Release();
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

        await _receiveLock.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            if (_peerClosed)
            {
                return 0;
            }

            TaskCompletionSource<ReceiveOutcome> pending =
                new(TaskCreationOptions.RunContinuationsAsynchronously);
            _pendingReceive = pending;
            nw_connection_receive(_connection, 1, (uint)buffer.Length, _receiveBlock);

            ReceiveOutcome outcome = await pending.Task.WaitAsync(cancellationToken)
                .ConfigureAwait(false);
            if (outcome.Closed || outcome.Data is null)
            {
                _peerClosed = true;
                return 0;
            }

            int length = Math.Min(outcome.Length, buffer.Length);
            outcome.Data.AsSpan(0, length).CopyTo(buffer.Span);
            return length;
        }
        finally
        {
            _pendingReceive = null;
            _receiveLock.Release();
        }
    }

    /// <inheritdoc />
    public override ValueTask CloseAsync(CancellationToken cancellationToken = default)
    {
        RequestCancel();
        return default;
    }

    // --- Block callbacks (instance) --------------------------------------------------------

    private void OnConfigureTls(IntPtr tlsOptions)
    {
        IntPtr sec = nw_tls_copy_sec_protocol_options(tlsOptions);
        if (sec == IntPtr.Zero)
        {
            return;
        }

        sec_protocol_options_set_min_tls_protocol_version(sec, TlsProtocolVersionDtls12);
        sec_protocol_options_set_max_tls_protocol_version(sec, TlsProtocolVersionDtls12);

        if (_isClient)
        {
            sec_protocol_options_set_verify_block(sec, _verifyBlock, _queue);
        }
        else if (_secIdentity != IntPtr.Zero)
        {
            sec_protocol_options_set_local_identity(sec, _secIdentity);
        }
    }

    private void OnState(int state, IntPtr error)
    {
        switch (state)
        {
            case NwConnectionStateReady:
                _ready.TrySetResult(true);
                break;
            case NwConnectionStateFailed:
                _ready.TrySetException(MakeError("nw_connection", error));
                FailPending(error);
                break;
            case NwConnectionStateCancelled:
                _ready.TrySetException(new DtlsException("The DTLS connection was cancelled."));
                FailPending(error);
                NotifyTerminal();
                break;
            default:
                break;
        }
    }

    private void OnListenerState(int state, IntPtr error)
    {
        switch (state)
        {
            case NwListenerStateReady:
                _listenerReady.TrySetResult(true);
                break;
            case NwListenerStateFailed:
                _listenerReady.TrySetException(MakeError("nw_listener", error));
                break;
            case NwListenerStateCancelled:
                _listenerReady.TrySetException(
                    new DtlsException("The DTLS listener was cancelled."));
                NotifyTerminal();
                break;
            default:
                break;
        }
    }

    private void OnNewConnection(IntPtr connection)
    {
        nw_retain(connection);
        if (!_newConnection.TrySetResult(connection))
        {
            // A connection was already accepted for this single-peer transport; drop extras.
            nw_connection_cancel(connection);
            nw_release(connection);
        }
    }

    private void OnSend(IntPtr error)
    {
        TaskCompletionSource<bool>? pending = _pendingSend;
        if (pending is null)
        {
            return;
        }

        if (error != IntPtr.Zero)
        {
            pending.TrySetException(MakeError("nw_connection_send", error));
        }
        else
        {
            pending.TrySetResult(true);
        }
    }

    private void OnReceive(IntPtr content, IntPtr context, byte isComplete, IntPtr error)
    {
        TaskCompletionSource<ReceiveOutcome>? pending = _pendingReceive;
        if (pending is null)
        {
            return;
        }

        if (error != IntPtr.Zero)
        {
            pending.TrySetException(MakeError("nw_connection_receive", error));
            return;
        }

        if (content == IntPtr.Zero)
        {
            pending.TrySetResult(new ReceiveOutcome(null, 0, isComplete != 0));
            return;
        }

        byte[] bytes = CopyDispatchData(content, out int length);
        pending.TrySetResult(new ReceiveOutcome(bytes, length, false));
    }

    private void OnVerify(IntPtr trust, IntPtr complete)
    {
        bool accept;
        try
        {
            accept = EvaluateRemoteCertificate(trust);
        }
        catch
        {
            accept = false;
        }

        NwBlock.InvokeBoolBlock(complete, accept);
    }

    private bool EvaluateRemoteCertificate(IntPtr trust)
    {
        if (_remoteValidation is null)
        {
            return true;
        }

        IntPtr secTrustRef = sec_trust_copy_ref(trust);
        if (secTrustRef == IntPtr.Zero)
        {
            return false;
        }

        IntPtr certData = IntPtr.Zero;
        try
        {
            IntPtr cert = SecureTransportInterop.SecTrustGetCertificateAtIndex(
                secTrustRef, IntPtr.Zero);
            if (cert == IntPtr.Zero)
            {
                return false;
            }

            certData = SecureTransportInterop.SecCertificateCopyData(cert);
            if (certData == IntPtr.Zero)
            {
                return false;
            }

            byte[] der = CopyCFData(certData);
            using X509Certificate2 certificate = LoadCertificate(der);
            return _remoteValidation(certificate, null, true);
        }
        finally
        {
            if (certData != IntPtr.Zero)
            {
                SecureTransportInterop.CFRelease(certData);
            }

            SecureTransportInterop.CFRelease(secTrustRef);
        }
    }

    private void FailPending(IntPtr error)
    {
        _pendingReceive?.TrySetException(MakeError("nw_connection", error));
        _pendingSend?.TrySetException(MakeError("nw_connection", error));
    }

    private void CaptureNegotiatedVersion()
    {
        if (_connection == IntPtr.Zero)
        {
            return;
        }

        IntPtr definition = nw_protocol_copy_tls_definition();
        IntPtr metadata = nw_connection_copy_protocol_metadata(_connection, definition);
        if (definition != IntPtr.Zero)
        {
            nw_release(definition);
        }

        if (metadata == IntPtr.Zero)
        {
            return;
        }

        ushort version = sec_protocol_metadata_get_negotiated_tls_protocol_version(metadata);
        nw_release(metadata);
        _negotiatedVersion = version switch
        {
            TlsProtocolVersionDtls12 => DtlsProtocolVersion.Dtls12,
            TlsProtocolVersionDtls10 => DtlsProtocolVersion.Dtls10,
            _ => DtlsProtocolVersion.Dtls12,
        };
    }

    // --- Certificate / identity ------------------------------------------------------------

    private unsafe void LoadServerIdentity(X509Certificate2 certificate)
    {
        string password = Convert.ToBase64String(RandomNumberGenerator.GetBytes(24));
        byte[] pfx = certificate.Export(X509ContentType.Pfx, password);
        byte[] passwordBytes = Encoding.UTF8.GetBytes(password + "\0");

        IntPtr pfxData = IntPtr.Zero;
        IntPtr passwordString = IntPtr.Zero;
        IntPtr options = IntPtr.Zero;
        try
        {
            fixed (byte* p = pfx)
            {
                pfxData = SecureTransportInterop.CFDataCreate(
                    IntPtr.Zero, (IntPtr)p, (IntPtr)pfx.Length);
            }

            passwordString = SecureTransportInterop.CFStringCreateWithCString(
                IntPtr.Zero, passwordBytes, SecureTransportInterop.KCFStringEncodingUtf8);

            IntPtr[] keys = { SecureTransportInterop.SecImportExportPassphrase };
            IntPtr[] values = { passwordString };
            options = SecureTransportInterop.CFDictionaryCreate(
                IntPtr.Zero,
                keys,
                values,
                (IntPtr)1,
                SecureTransportInterop.CFTypeDictionaryKeyCallBacks,
                SecureTransportInterop.CFTypeDictionaryValueCallBacks);

            int rc = SecureTransportInterop.SecPKCS12Import(pfxData, options, out _importedItems);
            if (rc != SecureTransportInterop.NoErr)
            {
                throw new DtlsException(
                    $"Network.framework SecPKCS12Import failed with OSStatus {rc}.");
            }

            if (_importedItems == IntPtr.Zero
                || (long)SecureTransportInterop.CFArrayGetCount(_importedItems) <= 0)
            {
                throw new DtlsException("Network.framework SecPKCS12Import produced no items.");
            }

            IntPtr item0 = SecureTransportInterop.CFArrayGetValueAtIndex(
                _importedItems, IntPtr.Zero);
            IntPtr identityRef = SecureTransportInterop.CFDictionaryGetValue(
                item0, SecureTransportInterop.SecImportItemIdentity);
            if (identityRef == IntPtr.Zero)
            {
                throw new DtlsException(
                    "Network.framework PKCS#12 import produced no identity.");
            }

            _secIdentity = sec_identity_create(identityRef);
            if (_secIdentity == IntPtr.Zero)
            {
                throw new DtlsException("Network.framework sec_identity_create returned null.");
            }
        }
        finally
        {
            if (options != IntPtr.Zero)
            {
                SecureTransportInterop.CFRelease(options);
            }

            if (passwordString != IntPtr.Zero)
            {
                SecureTransportInterop.CFRelease(passwordString);
            }

            if (pfxData != IntPtr.Zero)
            {
                SecureTransportInterop.CFRelease(pfxData);
            }

            CryptographicOperations.ZeroMemory(pfx);
        }
    }

    private static byte[] CopyCFData(IntPtr data)
    {
        IntPtr bytes = SecureTransportInterop.CFDataGetBytePtr(data);
        int length = (int)SecureTransportInterop.CFDataGetLength(data);
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

    // --- dispatch_data helpers -------------------------------------------------------------

    private static unsafe IntPtr CreateDispatchData(ReadOnlySpan<byte> data)
    {
        if (data.IsEmpty)
        {
            return IntPtr.Zero;
        }

        fixed (byte* p = data)
        {
            // A null destructor uses DISPATCH_DATA_DESTRUCTOR_DEFAULT, which copies the buffer.
            return dispatch_data_create((IntPtr)p, (UIntPtr)data.Length, IntPtr.Zero, IntPtr.Zero);
        }
    }

    private static byte[] CopyDispatchData(IntPtr content, out int length)
    {
        IntPtr map = dispatch_data_create_map(content, out IntPtr buffer, out UIntPtr size);
        length = (int)size;
        byte[] result = new byte[length];
        if (length > 0)
        {
            Marshal.Copy(buffer, result, 0, length);
        }

        if (map != IntPtr.Zero)
        {
            dispatch_release(map);
        }

        return result;
    }

    // --- Plumbing --------------------------------------------------------------------------

    private static CancellationTokenSource LinkTimeout(
        DtlsOptions options, CancellationToken cancellationToken, out CancellationToken token)
    {
        CancellationTokenSource cts =
            CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        cts.CancelAfter(options.HandshakeTimeout);
        token = cts.Token;
        return cts;
    }

    private static DtlsException MakeError(string operation, IntPtr error)
    {
        if (error == IntPtr.Zero)
        {
            return new DtlsException($"Network.framework {operation} failed.");
        }

        int code = nw_error_get_error_code(error);
        return new DtlsException(
            $"Network.framework {operation} failed with nw_error code {code}.");
    }

    private void ThrowIfDisposed()
    {
        if (Volatile.Read(ref _disposed) != 0 || Volatile.Read(ref _teardownStarted) != 0)
        {
            throw new ObjectDisposedException(nameof(NetworkDtlsConnection));
        }
    }

    /// <inheritdoc />
    protected override void Dispose(bool disposing)
    {
        if (Interlocked.Exchange(ref _disposed, 1) != 0)
        {
            return;
        }

        if (!disposing)
        {
            // Finalizer: the dispatch queue cannot be coordinated with safely here, so the
            // native handles are intentionally leaked. Disposal is the supported teardown path.
            return;
        }

        _relay?.Dispose();
        _sendLock.Dispose();
        _receiveLock.Dispose();
        RequestCancel();
    }

    private void RequestCancel()
    {
        if (Interlocked.Exchange(ref _teardownStarted, 1) != 0)
        {
            return;
        }

        // Network.framework delivers callbacks (including the terminal cancelled state) on the
        // dispatch queue. Freeing the GCHandle and native handles inline would race those
        // callbacks, so cancellation is requested now and the native cleanup runs from the
        // terminal callback (see FreeNativeOnce), once Network.framework is finished with the
        // connection and listener.
        int pending = 0;
        if (_connection != IntPtr.Zero)
        {
            pending++;
        }

        if (_listener != IntPtr.Zero)
        {
            pending++;
        }

        Volatile.Write(ref _pendingTerminal, pending);
        if (pending == 0)
        {
            FreeNativeOnce();
            return;
        }

        if (_connection != IntPtr.Zero)
        {
            nw_connection_cancel(_connection);
        }

        if (_listener != IntPtr.Zero)
        {
            nw_listener_cancel(_listener);
        }
    }

    private void NotifyTerminal()
    {
        if (Volatile.Read(ref _teardownStarted) == 0)
        {
            return;
        }

        if (Interlocked.Decrement(ref _pendingTerminal) <= 0)
        {
            FreeNativeOnce();
        }
    }

    private void FreeNativeOnce()
    {
        if (Interlocked.Exchange(ref _nativeFreed, 1) != 0)
        {
            return;
        }


        // The Objective-C block literals are intentionally not freed here: Network.framework
        // reads each block's flags during its own post-terminal release, so the small global
        // literals are leaked to keep that read valid. Everything else is released now that no
        // further callback can run for this connection.
        if (_connection != IntPtr.Zero)
        {
            nw_release(_connection);
            _connection = IntPtr.Zero;
        }

        if (_listener != IntPtr.Zero)
        {
            nw_release(_listener);
            _listener = IntPtr.Zero;
        }

        if (_importedItems != IntPtr.Zero)
        {
            SecureTransportInterop.CFRelease(_importedItems);
            _importedItems = IntPtr.Zero;
        }

        if (_queue != IntPtr.Zero)
        {
            dispatch_release(_queue);
            _queue = IntPtr.Zero;
        }

        if (_self.IsAllocated)
        {
            _self.Free();
        }
    }

    private readonly struct ReceiveOutcome
    {
        public ReceiveOutcome(byte[]? data, int length, bool closed)
        {
            Data = data;
            Length = length;
            Closed = closed;
        }

        public byte[]? Data { get; }

        public int Length { get; }

        public bool Closed { get; }
    }

    // --- Block trampolines (static UnmanagedCallersOnly) -----------------------------------

    private static NetworkDtlsConnection? Resolve(IntPtr block)
    {
        IntPtr context = NwBlock.GetContext(block);
        return context == IntPtr.Zero
            ? null
            : GCHandle.FromIntPtr(context).Target as NetworkDtlsConnection;
    }

    [UnmanagedCallersOnly(CallConvs = new[] { typeof(CallConvCdecl) })]
    private static void ConfigureTlsTrampoline(IntPtr block, IntPtr tlsOptions)
    {
        try
        {
            Resolve(block)?.OnConfigureTls(tlsOptions);
        }
        catch
        {
        }
    }

    [UnmanagedCallersOnly(CallConvs = new[] { typeof(CallConvCdecl) })]
    private static void StateTrampoline(IntPtr block, int state, IntPtr error)
    {
        try
        {
            Resolve(block)?.OnState(state, error);
        }
        catch
        {
        }
    }

    [UnmanagedCallersOnly(CallConvs = new[] { typeof(CallConvCdecl) })]
    private static void ListenerStateTrampoline(IntPtr block, int state, IntPtr error)
    {
        try
        {
            Resolve(block)?.OnListenerState(state, error);
        }
        catch
        {
        }
    }

    [UnmanagedCallersOnly(CallConvs = new[] { typeof(CallConvCdecl) })]
    private static void NewConnectionTrampoline(IntPtr block, IntPtr connection)
    {
        try
        {
            Resolve(block)?.OnNewConnection(connection);
        }
        catch
        {
        }
    }

    [UnmanagedCallersOnly(CallConvs = new[] { typeof(CallConvCdecl) })]
    private static void SendTrampoline(IntPtr block, IntPtr error)
    {
        try
        {
            Resolve(block)?.OnSend(error);
        }
        catch
        {
        }
    }

    [UnmanagedCallersOnly(CallConvs = new[] { typeof(CallConvCdecl) })]
    private static void ReceiveTrampoline(
        IntPtr block, IntPtr content, IntPtr context, byte isComplete, IntPtr error)
    {
        try
        {
            Resolve(block)?.OnReceive(content, context, isComplete, error);
        }
        catch
        {
        }
    }

    [UnmanagedCallersOnly(CallConvs = new[] { typeof(CallConvCdecl) })]
    private static void VerifyTrampoline(
        IntPtr block, IntPtr metadata, IntPtr trust, IntPtr complete)
    {
        try
        {
            Resolve(block)?.OnVerify(trust, complete);
        }
        catch
        {
        }
    }
}
#endif
