using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Threading;
using Xunit;

namespace Dtls.IntegrationTests;

/// <summary>
/// Groups the macOS certificate self-interop tests into a single, non-parallel xUnit collection.
/// Both the Secure Transport (DTLS 1.0) and Network.framework (DTLS 1.2) tests import PKCS#12
/// identities, which on macOS touch the login keychain. Running those imports concurrently can
/// trigger a transient "item could not be found in the keychain" failure, so the collection
/// disables parallelization to serialize keychain access.
/// </summary>
[CollectionDefinition(Name, DisableParallelization = true)]
public sealed class AppleKeychainGroup
{
    public const string Name = "AppleKeychain";
}

/// <summary>Shared certificate helpers for the macOS native-backend self-interop tests.</summary>
internal static class AppleTestCertificates
{
    /// <summary>
    /// Loads an exportable, persisted PKCS#12 identity, retrying on the transient macOS keychain
    /// error that can occur while importing identities under load.
    /// </summary>
    public static X509Certificate2 LoadImportable(byte[] pfx, string password)
    {
        const X509KeyStorageFlags flags =
            X509KeyStorageFlags.Exportable | X509KeyStorageFlags.PersistKeySet;

        for (int attempt = 0; ; attempt++)
        {
            try
            {
#if NET9_0_OR_GREATER
                return X509CertificateLoader.LoadPkcs12(pfx, password, flags);
#else
                return new X509Certificate2(pfx, password, flags);
#endif
            }
            catch (CryptographicException) when (attempt < 5)
            {
                Thread.Sleep(150);
            }
        }
    }
}
