// Copyright (c) marcschier. All rights reserved.
// Licensed under the MIT License. See LICENSE in the project root for license information.

#if NET8_0_OR_GREATER
using System;
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;
using System.Runtime.Versioning;

namespace Dtls.Interop.SecureTransport;

/// <summary>
/// P/Invoke surface for Apple's Secure Transport (the <c>Security.framework</c>) and the
/// supporting <c>CoreFoundation.framework</c>. Only the subset required to drive a DTLS 1.2
/// handshake over a datagram <c>SSLContextRef</c> and protect application records is declared
/// here. Both frameworks are referenced by their absolute on-disk paths so no resolver is
/// needed. All marshalled types are blittable and the read/write trampolines are
/// <see cref="UnmanagedCallersOnlyAttribute"/> static methods, so the declarations remain
/// Native AOT friendly.
/// </summary>
[SupportedOSPlatform("macos")]
internal static unsafe class SecureTransportInterop
{
    /// <summary>Absolute path to the system <c>Security.framework</c> binary.</summary>
    public const string Security =
        "/System/Library/Frameworks/Security.framework/Security";

    /// <summary>Absolute path to the system <c>CoreFoundation.framework</c> binary.</summary>
    public const string CoreFoundation =
        "/System/Library/Frameworks/CoreFoundation.framework/CoreFoundation";

    // SSLProtocolSide.
    public const int KSSLServerSide = 0;
    public const int KSSLClientSide = 1;

    // SSLConnectionType.
    public const int KSSLStreamType = 0;
    public const int KSSLDatagramType = 1;

    // SSLProtocol. DTLS 1.2 is value 11 in the Secure Transport enumeration.
    public const int KDtlsProtocol12 = 11;

    /// <summary>Secure Transport SSLProtocol value for DTLS 1.0.</summary>
    public const int KDtlsProtocol1 = 9;

    /// <summary>Secure Transport SSLProtocol value meaning "all protocols".</summary>
    public const int KSSLProtocolAll = 6;

    // SSLSessionOption.
    public const int KSSLSessionOptionBreakOnServerAuth = 0;

    // OSStatus result codes.
    public const int NoErr = 0;
    public const int ErrSSLWouldBlock = -9803;
    public const int ErrSSLClosedGraceful = -9805;
    public const int ErrSSLClosedAbort = -9806;
    public const int ErrSSLServerAuthCompleted = -9841;
    public const int ErrSSLClientCertRequested = -9842;

    // CFStringEncoding.
    public const uint KCFStringEncodingUtf8 = 0x08000100;

    private static readonly object ConstantsLock = new();
    private static volatile bool _constantsLoaded;
    private static IntPtr _secImportItemIdentity;
    private static IntPtr _secImportExportPassphrase;
    private static IntPtr _cfTypeArrayCallBacks;
    private static IntPtr _cfTypeDictionaryKeyCallBacks;
    private static IntPtr _cfTypeDictionaryValueCallBacks;

    /// <summary>The <c>kSecImportItemIdentity</c> dictionary key (a <c>CFStringRef</c>).</summary>
    public static IntPtr SecImportItemIdentity
    {
        get
        {
            EnsureConstants();
            return _secImportItemIdentity;
        }
    }

    /// <summary>The <c>kSecImportExportPassphrase</c> options key (a <c>CFStringRef</c>).</summary>
    public static IntPtr SecImportExportPassphrase
    {
        get
        {
            EnsureConstants();
            return _secImportExportPassphrase;
        }
    }

    /// <summary>Address of <c>kCFTypeArrayCallBacks</c> for retaining array values.</summary>
    public static IntPtr CFTypeArrayCallBacks
    {
        get
        {
            EnsureConstants();
            return _cfTypeArrayCallBacks;
        }
    }

    /// <summary>Address of <c>kCFTypeDictionaryKeyCallBacks</c>.</summary>
    public static IntPtr CFTypeDictionaryKeyCallBacks
    {
        get
        {
            EnsureConstants();
            return _cfTypeDictionaryKeyCallBacks;
        }
    }

    /// <summary>Address of <c>kCFTypeDictionaryValueCallBacks</c>.</summary>
    public static IntPtr CFTypeDictionaryValueCallBacks
    {
        get
        {
            EnsureConstants();
            return _cfTypeDictionaryValueCallBacks;
        }
    }

    /// <summary>The DTLS read callback function pointer handed to <c>SSLSetIOFuncs</c>.</summary>
    public static IntPtr ReadCallback =>
        (IntPtr)(delegate* unmanaged[Cdecl]<IntPtr, IntPtr, IntPtr, int>)&SslReadCallback;

    /// <summary>The DTLS write callback function pointer handed to <c>SSLSetIOFuncs</c>.</summary>
    public static IntPtr WriteCallback =>
        (IntPtr)(delegate* unmanaged[Cdecl]<IntPtr, IntPtr, IntPtr, int>)&SslWriteCallback;

    [DllImport(Security)]
    public static extern IntPtr SSLCreateContext(
        IntPtr alloc, int protocolSide, int connectionType);

    [DllImport(Security)]
    public static extern int SSLSetIOFuncs(IntPtr ctx, IntPtr readFunc, IntPtr writeFunc);

    [DllImport(Security)]
    public static extern int SSLSetConnection(IntPtr ctx, IntPtr connection);

    [DllImport(Security)]
    public static extern int SSLSetProtocolVersionMin(IntPtr ctx, int version);

    [DllImport(Security)]
    public static extern int SSLSetProtocolVersionEnabled(IntPtr ctx, int protocol, byte enable);

    [DllImport(Security)]
    public static extern int SSLSetProtocolVersionMax(IntPtr ctx, int version);

    [DllImport(Security)]
    public static extern int SSLSetCertificate(IntPtr ctx, IntPtr certRefs);

    [DllImport(Security)]
    public static extern int SSLSetSessionOption(IntPtr ctx, int option, byte value);

    [DllImport(Security)]
    public static extern int SSLHandshake(IntPtr ctx);

    [DllImport(Security)]
    public static extern int SSLRead(
        IntPtr ctx, IntPtr data, UIntPtr dataLength, out UIntPtr processed);

    [DllImport(Security)]
    public static extern int SSLWrite(
        IntPtr ctx, IntPtr data, UIntPtr dataLength, out UIntPtr processed);

    [DllImport(Security)]
    public static extern int SSLClose(IntPtr ctx);

    [DllImport(Security)]
    public static extern int SSLGetNegotiatedProtocolVersion(IntPtr ctx, out int protocol);

    [DllImport(Security)]
    public static extern int SSLCopyPeerTrust(IntPtr ctx, out IntPtr trust);

    [DllImport(Security)]
    public static extern int SecPKCS12Import(
        IntPtr pkcs12Data, IntPtr options, out IntPtr items);

    [DllImport(Security)]
    public static extern IntPtr SecTrustGetCertificateAtIndex(IntPtr trust, IntPtr ix);

    [DllImport(Security)]
    public static extern IntPtr SecCertificateCopyData(IntPtr cert);

    [DllImport(CoreFoundation)]
    public static extern void CFRelease(IntPtr cf);

    [DllImport(CoreFoundation)]
    public static extern IntPtr CFDataCreate(IntPtr alloc, IntPtr bytes, IntPtr length);

    [DllImport(CoreFoundation)]
    public static extern IntPtr CFArrayCreate(
        IntPtr alloc, IntPtr[] values, IntPtr numValues, IntPtr callbacks);

    [DllImport(CoreFoundation)]
    public static extern IntPtr CFArrayGetValueAtIndex(IntPtr array, IntPtr index);

    [DllImport(CoreFoundation)]
    public static extern IntPtr CFArrayGetCount(IntPtr array);

    [DllImport(CoreFoundation)]
    public static extern IntPtr CFDictionaryCreate(
        IntPtr alloc, IntPtr[] keys, IntPtr[] values, IntPtr n, IntPtr kcb, IntPtr vcb);

    [DllImport(CoreFoundation)]
    public static extern IntPtr CFDictionaryGetValue(IntPtr dict, IntPtr key);

    [DllImport(CoreFoundation)]
    public static extern IntPtr CFDataGetBytePtr(IntPtr data);

    [DllImport(CoreFoundation)]
    public static extern IntPtr CFDataGetLength(IntPtr data);

    [DllImport(CoreFoundation)]
    public static extern IntPtr CFStringCreateWithCString(
        IntPtr alloc, byte[] cStr, uint encoding);

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

            IntPtr security = NativeLibrary.Load(Security);
            IntPtr coreFoundation = NativeLibrary.Load(CoreFoundation);

            // The kSec* identifiers are exported as data symbols holding a CFStringRef, so
            // the export address must be dereferenced once to recover the string handle.
            _secImportItemIdentity =
                Marshal.ReadIntPtr(NativeLibrary.GetExport(security, "kSecImportItemIdentity"));
            _secImportExportPassphrase = Marshal.ReadIntPtr(
                NativeLibrary.GetExport(security, "kSecImportExportPassphrase"));

            // The kCFType*CallBacks identifiers are exported structures; CFArrayCreate and
            // CFDictionaryCreate take a pointer to the structure, which is the export address
            // itself (no dereference).
            _cfTypeArrayCallBacks =
                NativeLibrary.GetExport(coreFoundation, "kCFTypeArrayCallBacks");
            _cfTypeDictionaryKeyCallBacks =
                NativeLibrary.GetExport(coreFoundation, "kCFTypeDictionaryKeyCallBacks");
            _cfTypeDictionaryValueCallBacks =
                NativeLibrary.GetExport(coreFoundation, "kCFTypeDictionaryValueCallBacks");

            _constantsLoaded = true;
        }
    }

    [UnmanagedCallersOnly(CallConvs = new[] { typeof(CallConvCdecl) })]
    private static int SslReadCallback(IntPtr connection, IntPtr data, IntPtr dataLength)
    {
        try
        {
            if (GCHandle.FromIntPtr(connection).Target is not SecureTransportDtlsConnection conn)
            {
                Marshal.WriteIntPtr(dataLength, IntPtr.Zero);
                return ErrSSLClosedAbort;
            }

            return conn.HandleRead(data, dataLength);
        }
        catch
        {
            return ErrSSLClosedAbort;
        }
    }

    [UnmanagedCallersOnly(CallConvs = new[] { typeof(CallConvCdecl) })]
    private static int SslWriteCallback(IntPtr connection, IntPtr data, IntPtr dataLength)
    {
        try
        {
            if (GCHandle.FromIntPtr(connection).Target is not SecureTransportDtlsConnection conn)
            {
                Marshal.WriteIntPtr(dataLength, IntPtr.Zero);
                return ErrSSLClosedAbort;
            }

            return conn.HandleWrite(data, dataLength);
        }
        catch
        {
            return ErrSSLClosedAbort;
        }
    }
}
#endif
