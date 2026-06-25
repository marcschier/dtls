// Copyright (c) marcschier. All rights reserved.
// Licensed under the MIT License. See LICENSE in the project root for license information.

using System.Runtime.InteropServices;
using Dtls.Interop.Network;
using Dtls.Interop.OpenSsl;
using Dtls.Interop.Schannel;

namespace Dtls.Interop;

/// <summary>
/// Selects the native DTLS 1.0/1.2 backend appropriate for the current operating system.
/// </summary>
internal static class NativeDtlsBackend
{
    /// <summary>
    /// Returns the native backend for the current platform, or <see langword="null"/> if no native
    /// DTLS stack is integrated for this operating system. On iOS and Android no native backend is
    /// used, so the managed DTLS 1.2 engine serves as the universal fallback there.
    /// </summary>
    public static INativeDtlsBackend? ForCurrentPlatform()
    {
        if (RuntimeInformation.IsOSPlatform(OSPlatform.Linux))
        {
            return new OpenSslDtlsBackend();
        }

        if (RuntimeInformation.IsOSPlatform(OSPlatform.Windows))
        {
            return new SchannelDtlsBackend();
        }

        if (RuntimeInformation.IsOSPlatform(OSPlatform.OSX))
        {
            return new NetworkDtlsBackend();
        }

        return null;
    }
}


