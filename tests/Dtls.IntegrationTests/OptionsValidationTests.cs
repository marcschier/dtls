using Dtls;
using Xunit;

namespace Dtls.IntegrationTests;

/// <summary>Tests for option validation, including the DTLS 1.0 opt-in safeguard.</summary>
public sealed class OptionsValidationTests
{
    [Fact]
    public void ServerOptions_NoCredential_Throws()
    {
        DtlsServerOptions options = new();
        Assert.Throws<DtlsException>(options.Validate);
    }

    [Fact]
    public void ServerOptions_WithRawPublicKeys_Valid()
    {
        DtlsServerOptions options = new() { AllowRawPublicKeys = true };
        options.Validate();
    }

    [Fact]
    public void Dtls10_WithoutOptIn_Throws()
    {
        DtlsClientOptions options = new()
        {
            MinimumVersion = DtlsProtocolVersion.Dtls10,
            MaximumVersion = DtlsProtocolVersion.Dtls12,
        };
        Assert.Throws<DtlsException>(options.Validate);
    }

    [Fact]
    public void Dtls10_WithOptIn_Valid()
    {
        DtlsClientOptions options = new()
        {
            MinimumVersion = DtlsProtocolVersion.Dtls10,
            MaximumVersion = DtlsProtocolVersion.Dtls12,
            AllowDeprecatedDtls10 = true,
        };
        options.Validate();
    }

    [Fact]
    public void MinGreaterThanMax_Throws()
    {
        DtlsClientOptions options = new()
        {
            MinimumVersion = DtlsProtocolVersion.Dtls13,
            MaximumVersion = DtlsProtocolVersion.Dtls12,
        };
        Assert.Throws<DtlsException>(options.Validate);
    }

    [Fact]
    public void CipherSuites_SupportedEntries_Valid()
    {
        DtlsClientOptions options = new()
        {
            CipherSuites = new[]
            {
                DtlsCipherSuite.Aes256GcmSha384,
                DtlsCipherSuite.Aes128GcmSha256,
            },
        };
        options.Validate();
    }
}
