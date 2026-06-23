using System;
using System.Diagnostics;
using System.IO;
using System.Net;
using System.Net.Sockets;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Threading;
using System.Threading.Tasks;

namespace Dtls.Interop.Tests;

/// <summary>
/// A self-signed certificate written to temporary PEM files for use by the <c>openssl</c>
/// command-line tool, plus helpers for launching <c>s_server</c>/<c>s_client</c> and finding
/// a free loopback UDP port. The PEM files live under the test output directory and are
/// deleted on <see cref="Dispose"/>.
/// </summary>
internal sealed class OpenSslTestCertificate : IDisposable
{
    private readonly string _directory;

    private OpenSslTestCertificate(string directory, string certPath, string keyPath)
    {
        _directory = directory;
        CertificatePath = certPath;
        KeyPath = keyPath;
    }

    public string CertificatePath { get; }

    public string KeyPath { get; }

    public static OpenSslTestCertificate CreateEcdsa()
    {
        using ECDsa key = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        CertificateRequest request = new(
            "CN=dtls-openssl-cli", key, HashAlgorithmName.SHA256);
        DateTimeOffset now = DateTimeOffset.UtcNow;
        using X509Certificate2 certificate =
            request.CreateSelfSigned(now.AddMinutes(-5), now.AddHours(1));

        string directory = Path.Combine(
            AppContext.BaseDirectory, "openssl-interop-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(directory);
        string certPath = Path.Combine(directory, "cert.pem");
        string keyPath = Path.Combine(directory, "key.pem");

        File.WriteAllText(certPath, certificate.ExportCertificatePem());
        using (ECDsa privateKey = certificate.GetECDsaPrivateKey()!)
        {
            File.WriteAllText(keyPath, privateKey.ExportPkcs8PrivateKeyPem());
        }

        return new OpenSslTestCertificate(directory, certPath, keyPath);
    }

    public static int FindFreeUdpPort()
    {
        using Socket probe = new(AddressFamily.InterNetwork, SocketType.Dgram, ProtocolType.Udp);
        probe.Bind(new IPEndPoint(IPAddress.Loopback, 0));
        return ((IPEndPoint)probe.LocalEndPoint!).Port;
    }

    public void Dispose()
    {
        try
        {
            Directory.Delete(_directory, recursive: true);
        }
        catch (IOException)
        {
        }
        catch (UnauthorizedAccessException)
        {
        }
    }
}
