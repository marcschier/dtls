// Copyright (c) marcschier. All rights reserved.
// Licensed under the MIT License. See LICENSE in the project root for license information.

using System;
using System.Diagnostics;
using System.IO;
using System.Text;
using System.Threading.Tasks;

namespace Dtls.Interop.Tests;

/// <summary>
/// A thin wrapper around an <c>openssl</c> child process that asynchronously drains both
/// standard output and standard error into a single buffer (preventing pipe-buffer deadlocks)
/// and lets callers wait for a marker line or surface the captured output on failure.
/// </summary>
internal sealed class OpenSslProcess : IDisposable
{
    private readonly Process _process;
    private readonly StringBuilder _output = new();
    private readonly object _gate = new();

    private OpenSslProcess(Process process)
    {
        _process = process;
    }

    public StreamWriter StandardInput => _process.StandardInput;

    public string Output
    {
        get
        {
            lock (_gate)
            {
                return _output.ToString();
            }
        }
    }

    public static OpenSslProcess Start(string arguments)
    {
        ProcessStartInfo info = new("openssl", arguments)
        {
            RedirectStandardInput = true,
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            UseShellExecute = false,
            CreateNoWindow = true,
        };

        Process process = Process.Start(info)
            ?? throw new InvalidOperationException("Failed to start the openssl process.");

        OpenSslProcess harness = new(process);
        process.OutputDataReceived += harness.OnData;
        process.ErrorDataReceived += harness.OnData;
        process.BeginOutputReadLine();
        process.BeginErrorReadLine();
        return harness;
    }

    public async Task WaitForMarkerAsync(string marker, TimeSpan timeout)
    {
        Stopwatch stopwatch = Stopwatch.StartNew();
        while (stopwatch.Elapsed < timeout)
        {
            if (Output.Contains(marker, StringComparison.Ordinal))
            {
                return;
            }

            if (_process.HasExited)
            {
                throw new InvalidOperationException(
                    $"openssl exited early (code {_process.ExitCode}) before emitting "
                    + $"'{marker}'. Output:{Environment.NewLine}{Output}");
            }

            await Task.Delay(50).ConfigureAwait(false);
        }

        throw new TimeoutException(
            $"openssl did not emit '{marker}' within {timeout}. Output:"
            + $"{Environment.NewLine}{Output}");
    }

    private void OnData(object sender, DataReceivedEventArgs e)
    {
        if (e.Data is null)
        {
            return;
        }

        lock (_gate)
        {
            _output.AppendLine(e.Data);
        }
    }

    public void Dispose()
    {
        try
        {
            if (!_process.HasExited)
            {
                _process.Kill(entireProcessTree: true);
            }
        }
        catch (InvalidOperationException)
        {
        }
        catch (System.ComponentModel.Win32Exception)
        {
        }
        finally
        {
            _process.Dispose();
        }
    }
}
