using System.Collections.Generic;
using Dtls.Crypto;

namespace Dtls.Internal;

/// <summary>
/// Maps the public <see cref="DtlsCipherSuite"/> allow-list configured on
/// <see cref="DtlsOptions"/> to the internal <see cref="Dtls13CipherSuite"/> descriptors,
/// filtering out suites that are not supported on the current target framework.
/// </summary>
internal static class CipherSuitePolicy
{
    /// <summary>
    /// Resolves <paramref name="configured"/> to the ordered set of supported cipher suite
    /// descriptors. An empty or null list yields <see cref="Dtls13CipherSuite.SupportedDefault"/>.
    /// </summary>
    /// <param name="configured">The configured preference/allow-list (may be empty).</param>
    /// <returns>The supported descriptors in preference order; never empty.</returns>
    public static IReadOnlyList<Dtls13CipherSuite> Resolve(
        IReadOnlyList<DtlsCipherSuite>? configured)
    {
        if (configured is null || configured.Count == 0)
        {
            return Dtls13CipherSuite.SupportedDefault;
        }

        List<Dtls13CipherSuite> resolved = new(configured.Count);
        foreach (DtlsCipherSuite candidate in configured)
        {
            if (Dtls13CipherSuite.TryGet((ushort)candidate, out Dtls13CipherSuite suite)
                && !resolved.Contains(suite))
            {
                resolved.Add(suite);
            }
        }

        return resolved.Count > 0 ? resolved : Dtls13CipherSuite.SupportedDefault;
    }

    /// <summary>
    /// Indicates whether at least one entry in <paramref name="configured"/> is supported
    /// on the current target framework.
    /// </summary>
    /// <param name="configured">The configured allow-list.</param>
    /// <returns><see langword="true"/> when any entry is supported here.</returns>
    public static bool HasSupportedEntry(IReadOnlyList<DtlsCipherSuite> configured)
    {
        foreach (DtlsCipherSuite candidate in configured)
        {
            if (Dtls13CipherSuite.IsSupported((ushort)candidate))
            {
                return true;
            }
        }

        return false;
    }
}
