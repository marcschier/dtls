// Copyright (c) marcschier. All rights reserved.
// Licensed under the MIT License. See LICENSE in the project root for license information.

#if NET8_0_OR_GREATER
using System;
using System.Reflection;
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;
using System.Threading;

namespace Dtls.Interop.OpenSsl;

/// <summary>
/// Maps the unversioned OpenSSL import names declared by <see cref="OpenSslInterop"/> to the
/// concrete versioned shared objects shipped by the host distribution. Linux packages
/// install <c>libssl.so.3</c> / <c>libcrypto.so.3</c> (OpenSSL 3.x) or <c>*.so.1.1</c>
/// (OpenSSL 1.1.x); the development symlinks (<c>libssl.so</c>) are frequently absent. The
/// resolver is registered once from a module initializer so the mapping is in place before
/// the first P/Invoke is marshalled, on every platform (it is inert where OpenSSL is unused).
/// </summary>
internal static class OpenSslLibraryResolver
{
    private static readonly string[] SslCandidates =
    {
        "libssl.so.3",
        "libssl.so.1.1",
        "libssl.so",
    };

    private static readonly string[] CryptoCandidates =
    {
        "libcrypto.so.3",
        "libcrypto.so.1.1",
        "libcrypto.so",
    };

    private static int _registered;

    /// <summary>Registers the resolver as the module loads (runs on every platform).</summary>
    // CA2255: this library deliberately registers its native-library resolver as the module
    // loads so the mapping is in place before any DllImport in this assembly is marshalled.
#pragma warning disable CA2255
    [ModuleInitializer]
    internal static void Initialize()
    {
        Register();
    }
#pragma warning restore CA2255

    /// <summary>Registers the resolver if it has not already been registered.</summary>
    internal static void Register()
    {
        if (Interlocked.Exchange(ref _registered, 1) != 0)
        {
            return;
        }

        NativeLibrary.SetDllImportResolver(
            typeof(OpenSslLibraryResolver).Assembly, Resolve);
    }

    private static IntPtr Resolve(
        string libraryName, Assembly assembly, DllImportSearchPath? searchPath)
    {
        string[]? candidates = libraryName switch
        {
            "libssl" => SslCandidates,
            "libcrypto" => CryptoCandidates,
            _ => null,
        };

        if (candidates is null)
        {
            return IntPtr.Zero;
        }

        foreach (string candidate in candidates)
        {
            if (NativeLibrary.TryLoad(candidate, out IntPtr handle))
            {
                return handle;
            }
        }

        return IntPtr.Zero;
    }
}
#endif
