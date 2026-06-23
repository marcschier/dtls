using System;
using System.Diagnostics;

namespace Dtls.Interop.Tests;

/// <summary>The result of probing for the OpenSSL command-line tool.</summary>
internal readonly struct OpenSslResult
{
    public OpenSslResult(bool available, string version)
    {
        Available = available;
        Version = version;
    }

    /// <summary>Whether the <c>openssl</c> executable could be launched.</summary>
    public bool Available { get; }

    /// <summary>The version string reported by <c>openssl version</c>, if available.</summary>
    public string Version { get; }
}

/// <summary>
/// Thin wrapper that runs the <c>openssl</c> command-line tool. CI installs OpenSSL on
/// every platform so that interop tests can run our endpoints against
/// <c>openssl s_server</c> / <c>s_client</c>. Locally OpenSSL may be absent, in which case
/// the probe reports unavailability and interop tests treat themselves as inconclusive.
/// </summary>
internal static class OpenSslCli
{
    public static OpenSslResult TryGetVersion()
    {
        try
        {
            ProcessStartInfo info = new("openssl", "version")
            {
                RedirectStandardOutput = true,
                RedirectStandardError = true,
                UseShellExecute = false,
                CreateNoWindow = true,
            };

            using Process? process = Process.Start(info);
            if (process is null)
            {
                return new OpenSslResult(false, string.Empty);
            }

            string output = process.StandardOutput.ReadToEnd();
            process.WaitForExit(10_000);
            return new OpenSslResult(true, output.Trim());
        }
        catch (Exception ex) when (ex is System.ComponentModel.Win32Exception
            or InvalidOperationException
            or PlatformNotSupportedException)
        {
            return new OpenSslResult(false, string.Empty);
        }
    }
}
