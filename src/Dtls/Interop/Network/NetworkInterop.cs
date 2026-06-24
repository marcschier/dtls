#if NET8_0_OR_GREATER
using System;
using System.Runtime.InteropServices;
using System.Runtime.Versioning;

namespace Dtls.Interop.Network;

/// <summary>
/// P/Invoke surface for Apple's <c>Network.framework</c> (the modern <c>nw_*</c> datagram and
/// security API), the supporting <c>libdispatch</c> queues, and the Objective-C Block runtime.
/// Network.framework's secure-UDP transport negotiates DTLS (defaulting to DTLS 1.2), which the
/// deprecated Secure Transport API could not select on recent macOS. Only the subset needed to
/// drive a DTLS 1.2 <c>nw_connection</c>/<c>nw_listener</c> handshake and exchange application
/// datagrams is declared here. All callbacks are Objective-C blocks; see <see cref="NwBlock"/>
/// for the block ABI shim. The block trampolines are static <c>UnmanagedCallersOnly</c> methods,
/// so the declarations remain Native AOT friendly.
/// </summary>
[SupportedOSPlatform("macos")]
internal static unsafe class NetworkInterop
{
    /// <summary>Absolute path to the system <c>Network.framework</c> binary.</summary>
    public const string Network =
        "/System/Library/Frameworks/Network.framework/Network";

    /// <summary>
    /// Absolute path to <c>libSystem</c>, which re-exports dispatch and the Block ABI.
    /// </summary>
    public const string LibSystem = "/usr/lib/libSystem.dylib";

    // tls_protocol_version_t (Security/SecProtocolTypes.h). DTLS versions use the one's-complement
    // wire encoding: DTLS 1.0 = 0xFEFF, DTLS 1.2 = 0xFEFD.
    public const ushort TlsProtocolVersionDtls10 = 0xFEFF;
    public const ushort TlsProtocolVersionDtls12 = 0xFEFD;

    // nw_connection_state_t.
    public const int NwConnectionStateInvalid = 0;
    public const int NwConnectionStateWaiting = 1;
    public const int NwConnectionStatePreparing = 2;
    public const int NwConnectionStateReady = 3;
    public const int NwConnectionStateFailed = 4;
    public const int NwConnectionStateCancelled = 5;

    // nw_listener_state_t.
    public const int NwListenerStateInvalid = 0;
    public const int NwListenerStateWaiting = 1;
    public const int NwListenerStateReady = 2;
    public const int NwListenerStateFailed = 3;
    public const int NwListenerStateCancelled = 4;

    // --- nw_endpoint / nw_parameters -------------------------------------------------------

    [DllImport(Network)]
    public static extern IntPtr nw_endpoint_create_host(
        [MarshalAs(UnmanagedType.LPUTF8Str)] string hostname,
        [MarshalAs(UnmanagedType.LPUTF8Str)] string port);

    [DllImport(Network)]
    public static extern IntPtr nw_parameters_create_secure_udp(
        IntPtr configureTlsBlock, IntPtr configureUdpBlock);

    [DllImport(Network)]
    public static extern IntPtr nw_tls_copy_sec_protocol_options(IntPtr tlsOptions);

    // --- sec_protocol_options / sec_identity ----------------------------------------------

    [DllImport(Network)]
    public static extern void sec_protocol_options_set_min_tls_protocol_version(
        IntPtr secOptions, ushort version);

    [DllImport(Network)]
    public static extern void sec_protocol_options_set_max_tls_protocol_version(
        IntPtr secOptions, ushort version);

    [DllImport(Network)]
    public static extern void sec_protocol_options_set_local_identity(
        IntPtr secOptions, IntPtr secIdentity);

    [DllImport(Network)]
    public static extern void sec_protocol_options_set_verify_block(
        IntPtr secOptions, IntPtr verifyBlock, IntPtr queue);

    [DllImport(Network)]
    public static extern IntPtr sec_identity_create(IntPtr secIdentityRef);

    [DllImport(Network)]
    public static extern ushort sec_protocol_metadata_get_negotiated_tls_protocol_version(
        IntPtr metadata);

    [DllImport(Network)]
    public static extern IntPtr sec_trust_copy_ref(IntPtr secTrust);

    // --- nw_connection ---------------------------------------------------------------------

    [DllImport(Network)]
    public static extern IntPtr nw_connection_create(IntPtr endpoint, IntPtr parameters);

    [DllImport(Network)]
    public static extern void nw_connection_set_queue(IntPtr connection, IntPtr queue);

    [DllImport(Network)]
    public static extern void nw_connection_set_state_changed_handler(
        IntPtr connection, IntPtr handlerBlock);

    [DllImport(Network)]
    public static extern void nw_connection_start(IntPtr connection);

    [DllImport(Network)]
    public static extern void nw_connection_cancel(IntPtr connection);

    [DllImport(Network)]
    public static extern void nw_connection_send(
        IntPtr connection,
        IntPtr content,
        IntPtr context,
        byte isComplete,
        IntPtr completionBlock);

    [DllImport(Network)]
    public static extern void nw_connection_receive(
        IntPtr connection,
        uint minimumIncompleteLength,
        uint maximumLength,
        IntPtr completionBlock);

    [DllImport(Network)]
    public static extern IntPtr nw_connection_copy_protocol_metadata(
        IntPtr connection, IntPtr definition);

    [DllImport(Network)]
    public static extern IntPtr nw_protocol_copy_tls_definition();

    // --- nw_listener -----------------------------------------------------------------------

    [DllImport(Network)]
    public static extern IntPtr nw_listener_create(IntPtr parameters);

    [DllImport(Network)]
    public static extern void nw_listener_set_queue(IntPtr listener, IntPtr queue);

    [DllImport(Network)]
    public static extern void nw_listener_set_state_changed_handler(
        IntPtr listener, IntPtr handlerBlock);

    [DllImport(Network)]
    public static extern void nw_listener_set_new_connection_handler(
        IntPtr listener, IntPtr handlerBlock);

    [DllImport(Network)]
    public static extern void nw_listener_start(IntPtr listener);

    [DllImport(Network)]
    public static extern void nw_listener_cancel(IntPtr listener);

    [DllImport(Network)]
    public static extern ushort nw_listener_get_port(IntPtr listener);

    // --- nw_error --------------------------------------------------------------------------

    [DllImport(Network)]
    public static extern int nw_error_get_error_code(IntPtr error);

    // --- nw object lifetime ----------------------------------------------------------------

    [DllImport(Network)]
    public static extern IntPtr nw_retain(IntPtr obj);

    [DllImport(Network)]
    public static extern void nw_release(IntPtr obj);

    // --- libdispatch -----------------------------------------------------------------------

    [DllImport(LibSystem)]
    public static extern IntPtr dispatch_queue_create(
        [MarshalAs(UnmanagedType.LPUTF8Str)] string label, IntPtr attr);

    [DllImport(LibSystem)]
    public static extern IntPtr dispatch_data_create(
        IntPtr buffer, UIntPtr size, IntPtr queue, IntPtr destructor);

    [DllImport(LibSystem)]
    public static extern IntPtr dispatch_data_create_map(
        IntPtr data, out IntPtr bufferPtr, out UIntPtr sizePtr);

    [DllImport(LibSystem)]
    public static extern UIntPtr dispatch_data_get_size(IntPtr data);

    [DllImport(LibSystem)]
    public static extern void dispatch_release(IntPtr obj);

    private static readonly object ConstantsLock = new();
    private static volatile bool _constantsLoaded;
    private static IntPtr _nsConcreteGlobalBlock;
    private static IntPtr _defaultProtocolConfiguration;
    private static IntPtr _defaultMessageContext;

    /// <summary>Address of <c>_NSConcreteGlobalBlock</c>, the isa for an immortal block.</summary>
    public static IntPtr NSConcreteGlobalBlock
    {
        get
        {
            EnsureConstants();
            return _nsConcreteGlobalBlock;
        }
    }

    /// <summary>
    /// The <c>NW_PARAMETERS_DEFAULT_CONFIGURATION</c> sentinel block used to keep a protocol at its
    /// default configuration (passed as the UDP configuration of a secure-UDP parameter set).
    /// </summary>
    public static IntPtr DefaultProtocolConfiguration
    {
        get
        {
            EnsureConstants();
            return _defaultProtocolConfiguration;
        }
    }

    /// <summary>
    /// The <c>NW_CONNECTION_DEFAULT_MESSAGE_CONTEXT</c> content context for datagrams.
    /// </summary>
    public static IntPtr DefaultMessageContext
    {
        get
        {
            EnsureConstants();
            return _defaultMessageContext;
        }
    }

    private static void EnsureConstants()
    {
        if (_constantsLoaded)
        {
            return;
        }

        lock (ConstantsLock)
        {
            if (_constantsLoaded)
            {
                return;
            }

            IntPtr system = NativeLibrary.Load(LibSystem);
            IntPtr network = NativeLibrary.Load(Network);

            // _NSConcreteGlobalBlock is the isa value itself: the export address is the class
            // structure that the block literal's isa field must reference.
            _nsConcreteGlobalBlock = NativeLibrary.GetExport(system, "_NSConcreteGlobalBlock");

            // The NW sentinels are exported as block pointers held at the export address, so the
            // address must be dereferenced once to recover the block handle.
            _defaultProtocolConfiguration = Marshal.ReadIntPtr(NativeLibrary.GetExport(
                network, "_nw_parameters_configure_protocol_default_configuration"));
            _defaultMessageContext = Marshal.ReadIntPtr(NativeLibrary.GetExport(
                network, "_nw_content_context_default_message"));

            _constantsLoaded = true;
        }
    }
}
#endif
