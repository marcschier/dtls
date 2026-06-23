using System.Runtime.InteropServices;
using Dtls.Interop.OpenSsl;
using Dtls.Interop.Schannel;
using Dtls.Interop.SecureTransport;

namespace Dtls.Interop;

/// <summary>
/// Selects the native DTLS 1.0/1.2 backend appropriate for the current operating system.
/// </summary>
internal static class NativeDtlsBackend
{
    /// <summary>
    /// Returns the native backend for the current platform, or <see langword="null"/> if
    /// no native DTLS stack is integrated for this operating system.
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
            return new SecureTransportDtlsBackend();
        }

        return null;
    }
}
