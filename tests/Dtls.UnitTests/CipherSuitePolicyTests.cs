// Copyright (c) marcschier. All rights reserved.
// Licensed under the MIT License. See LICENSE in the project root for license information.

using System.Collections.Generic;
using Dtls.Crypto;
using Dtls.Internal;
using Xunit;

namespace Dtls.UnitTests;

/// <summary>
/// Tests for <see cref="CipherSuitePolicy"/>: resolving the public allow-list to internal
/// descriptors, with deduplication and the documented fallbacks to the default suite set, plus
/// the support probe used by options validation. These selection/fallback branches are not
/// directly asserted by the handshake or options-validation tests.
/// </summary>
public sealed class CipherSuitePolicyTests
{
    // A 16-bit value that is not a registered DTLS 1.3 suite, so it is unsupported on every
    // target framework (independent of whether AES-CCM is available).
    private const ushort UnknownSuite = 0x9999;

    [Fact]
    public void Resolve_Null_ReturnsSupportedDefault()
    {
        Assert.Same(Dtls13CipherSuite.SupportedDefault, CipherSuitePolicy.Resolve(null));
    }

    [Fact]
    public void Resolve_Empty_ReturnsSupportedDefault()
    {
        IReadOnlyList<DtlsCipherSuite> configured = new List<DtlsCipherSuite>();

        Assert.Same(Dtls13CipherSuite.SupportedDefault, CipherSuitePolicy.Resolve(configured));
    }

    [Fact]
    public void Resolve_PreservesConfiguredOrder()
    {
        IReadOnlyList<DtlsCipherSuite> configured = new[]
        {
            DtlsCipherSuite.Aes256GcmSha384,
            DtlsCipherSuite.Aes128GcmSha256,
        };

        IReadOnlyList<Dtls13CipherSuite> resolved = CipherSuitePolicy.Resolve(configured);

        Assert.Equal(2, resolved.Count);
        Assert.Equal(0x1302, resolved[0].Id);
        Assert.Equal(0x1301, resolved[1].Id);
    }

    [Fact]
    public void Resolve_DeduplicatesRepeatedSuites()
    {
        IReadOnlyList<DtlsCipherSuite> configured = new[]
        {
            DtlsCipherSuite.Aes128GcmSha256,
            DtlsCipherSuite.Aes128GcmSha256,
        };

        IReadOnlyList<Dtls13CipherSuite> resolved = CipherSuitePolicy.Resolve(configured);

        Assert.Single(resolved);
        Assert.Equal(0x1301, resolved[0].Id);
    }

    [Fact]
    public void Resolve_AllUnsupported_FallsBackToDefault()
    {
        IReadOnlyList<DtlsCipherSuite> configured = new[] { (DtlsCipherSuite)UnknownSuite };

        Assert.Same(Dtls13CipherSuite.SupportedDefault, CipherSuitePolicy.Resolve(configured));
    }

    [Fact]
    public void HasSupportedEntry_WithSupportedSuite_ReturnsTrue()
    {
        IReadOnlyList<DtlsCipherSuite> configured = new[] { DtlsCipherSuite.Aes128GcmSha256 };

        Assert.True(CipherSuitePolicy.HasSupportedEntry(configured));
    }

    [Fact]
    public void HasSupportedEntry_OnlyUnknownSuite_ReturnsFalse()
    {
        IReadOnlyList<DtlsCipherSuite> configured = new[] { (DtlsCipherSuite)UnknownSuite };

        Assert.False(CipherSuitePolicy.HasSupportedEntry(configured));
    }

    [Fact]
    public void HasSupportedEntry_Empty_ReturnsFalse()
    {
        Assert.False(CipherSuitePolicy.HasSupportedEntry(new List<DtlsCipherSuite>()));
    }
}
