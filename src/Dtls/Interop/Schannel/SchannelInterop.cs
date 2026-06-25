// Copyright (c) marcschier. All rights reserved.
// Licensed under the MIT License. See LICENSE in the project root for license information.

using System;
using System.Runtime.InteropServices;
using System.Runtime.Versioning;

namespace Dtls.Interop.Schannel;

/// <summary>
/// P/Invoke surface for the Windows Schannel security support provider (SSPI), exposed by
/// <c>secur32.dll</c> and <c>crypt32.dll</c>. Only the subset required to drive a DTLS 1.2
/// handshake and protect application records over datagrams is declared here. All marshalled
/// types are blittable so the declarations remain Native AOT friendly.
/// </summary>
[SupportedOSPlatform("windows")]
internal static class SchannelInterop
{
    /// <summary>The Schannel security package name (Unicode entry point).</summary>
    public const string UnifiedSecurityProtocolProvider =
        "Microsoft Unified Security Protocol Provider";

    public const int SchannelCredVersion = 4;
    public const int SecbufferVersion = 0;

    // Credential use.
    public const int SecpkgCredInbound = 1;
    public const int SecpkgCredOutbound = 2;

    // Enabled-protocol bits.
    public const uint SpProtDtls1_2Client = 0x00080000;
    public const uint SpProtDtls1_2Server = 0x00040000;

    // SCHANNEL_CRED.dwFlags.
    public const uint SchCredManualCredValidation = 0x00000008;
    public const uint SchCredNoDefaultCreds = 0x00000010;
    public const uint SchCredNoServernameCheck = 0x00000004;

    // ISC/ASC request flags (shared bit values, except EXTENDED_ERROR which differs).
    public const int ReqReplayDetect = 0x00000004;
    public const int ReqSequenceDetect = 0x00000008;
    public const int ReqConfidentiality = 0x00000010;
    public const int ReqAllocateMemory = 0x00000100;
    public const int ReqDatagram = 0x00000400;
    public const int IscReqExtendedError = 0x00004000;
    public const int AscReqExtendedError = 0x00008000;

    public const int SecurityNativeDrep = 0x00000010;

    // Buffer types.
    public const uint SecbufferEmpty = 0;
    public const uint SecbufferData = 1;
    public const uint SecbufferToken = 2;
    public const uint SecbufferExtra = 5;
    public const uint SecbufferStreamTrailer = 6;
    public const uint SecbufferStreamHeader = 7;
    public const uint SecbufferAlert = 17;

    // QueryContextAttributes selectors.
    public const int SecpkgAttrStreamSizes = 4;
    public const int SecpkgAttrRemoteCertContext = 0x53;

    // ApplyControlToken control codes.
    public const uint SchannelShutdown = 1;

    // SECURITY_STATUS values.
    public const int SecEOk = 0x00000000;
    public const int SecIContinueNeeded = 0x00090312;
    public const int SecIContextExpired = 0x00090317;
    public const int SecIRenegotiate = 0x00090321;
    public const int SecIMessageFragment = 0x00090364;

    public const int SecEIncompleteMessage = unchecked((int)0x80090318);
    public const int SecEContextExpired = unchecked((int)0x80090317);

    [DllImport("secur32.dll", CharSet = CharSet.Unicode, EntryPoint = "AcquireCredentialsHandleW")]
    [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
    public static extern int AcquireCredentialsHandle(
        string? pszPrincipal,
        string pszPackage,
        int fCredentialUse,
        IntPtr pvLogonId,
        IntPtr pAuthData,
        IntPtr pGetKeyFn,
        IntPtr pvGetKeyArgument,
        ref SecurityHandle phCredential,
        out long ptsExpiry);

    [DllImport("secur32.dll")]
    [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
    public static extern int FreeCredentialsHandle(ref SecurityHandle phCredential);

    [DllImport("secur32.dll", CharSet = CharSet.Unicode, EntryPoint = "InitializeSecurityContextW")]
    [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
    public static extern int InitializeSecurityContext(
        ref SecurityHandle phCredential,
        IntPtr phContext,
        string? pszTargetName,
        int fContextReq,
        int reserved1,
        int targetDataRep,
        IntPtr pInput,
        int reserved2,
        IntPtr phNewContext,
        IntPtr pOutput,
        out int pfContextAttr,
        out long ptsExpiry);

    [DllImport("secur32.dll", EntryPoint = "AcceptSecurityContext")]
    [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
    public static extern int AcceptSecurityContext(
        ref SecurityHandle phCredential,
        IntPtr phContext,
        IntPtr pInput,
        int fContextReq,
        int targetDataRep,
        IntPtr phNewContext,
        IntPtr pOutput,
        out int pfContextAttr,
        out long ptsTimeStamp);

    [DllImport("secur32.dll", CharSet = CharSet.Unicode, EntryPoint = "QueryContextAttributesW")]
    [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
    public static extern int QueryContextAttributes(
        ref SecurityHandle phContext,
        int ulAttribute,
        IntPtr pBuffer);

    [DllImport("secur32.dll")]
    [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
    public static extern int EncryptMessage(
        ref SecurityHandle phContext,
        uint fqop,
        IntPtr pMessage,
        uint messageSeqNo);

    [DllImport("secur32.dll")]
    [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
    public static extern int DecryptMessage(
        ref SecurityHandle phContext,
        IntPtr pMessage,
        uint messageSeqNo,
        out uint pfqop);

    [DllImport("secur32.dll")]
    [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
    public static extern int ApplyControlToken(
        ref SecurityHandle phContext,
        IntPtr pInput);

    [DllImport("secur32.dll")]
    [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
    public static extern int DeleteSecurityContext(ref SecurityHandle phContext);

    [DllImport("secur32.dll")]
    [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
    public static extern int FreeContextBuffer(IntPtr pvContextBuffer);

    [DllImport("crypt32.dll")]
    [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
    public static extern IntPtr CertFreeCertificateContext(IntPtr pCertContext);
}

/// <summary>An SSPI <c>SecHandle</c>/<c>CredHandle</c>/<c>CtxtHandle</c> (two pointers).</summary>
[StructLayout(LayoutKind.Sequential)]
internal struct SecurityHandle
{
    public IntPtr Lower;
    public IntPtr Upper;
}

/// <summary>A single SSPI security buffer (<c>SecBuffer</c>).</summary>
[StructLayout(LayoutKind.Sequential)]
internal struct SecBuffer
{
    public uint CbBuffer;
    public uint BufferType;
    public IntPtr PvBuffer;
}

/// <summary>An SSPI buffer descriptor (<c>SecBufferDesc</c>).</summary>
[StructLayout(LayoutKind.Sequential)]
internal struct SecBufferDesc
{
    public uint UlVersion;
    public uint CBuffers;
    public IntPtr PBuffers;
}

/// <summary>Record framing sizes reported by <c>SECPKG_ATTR_STREAM_SIZES</c>.</summary>
[StructLayout(LayoutKind.Sequential)]
internal struct SecPkgContextStreamSizes
{
    public uint CbHeader;
    public uint CbTrailer;
    public uint CbMaximumMessage;
    public uint CBuffers;
    public uint CbBlockSize;
}

/// <summary>The legacy <c>SCHANNEL_CRED</c> credential structure (version 4).</summary>
[StructLayout(LayoutKind.Sequential)]
internal struct SchannelCred
{
    public int DwVersion;
    public int CCreds;
    public IntPtr PaCred;
    public IntPtr HRootStore;
    public int CMappers;
    public IntPtr AphMappers;
    public int CSupportedAlgs;
    public IntPtr PalgSupportedAlgs;
    public uint GrbitEnabledProtocols;
    public uint DwMinimumCipherStrength;
    public uint DwMaximumCipherStrength;
    public uint DwSessionLifespan;
    public uint DwFlags;
    public uint DwCredFormat;
}
