# Supported protocols

Dtls supports DTLS 1.0, DTLS 1.2, and DTLS 1.3 across Linux, Windows, and macOS with a hybrid native/managed architecture.

## Version and platform matrix

| DTLS version | Linux | Windows | macOS | Engine | Default |
| --- | --- | --- | --- | --- | --- |
| DTLS 1.0 | OpenSSL | Schannel/SSPI | Secure Transport | Native | Off by default; explicit opt-in required |
| DTLS 1.2 | OpenSSL | Schannel/SSPI | Network.framework | Native | Enabled |
| DTLS 1.3 | Managed C# with BCL crypto | Managed C# with BCL crypto | Managed C# with BCL crypto | Managed | Enabled where policy allows |

OpenSSL, Schannel, and Apple Secure Transport / Network.framework do not currently provide a mainstream native DTLS 1.3 stack, so DTLS 1.3 is implemented in managed code and uses BCL cryptographic primitives backed by the operating system crypto provider.

### macOS native backend (Network.framework, Secure Transport fallback)

On macOS the native DTLS path prefers Apple's modern **Network.framework**, whose secure-UDP transport negotiates **DTLS 1.2** (verified on the macOS CI runner, certificate auth). Because Network.framework owns its own UDP socket and exposes an asynchronous, Objective-C block-based API, the backend runs the DTLS endpoint over a private loopback socket and bridges the encrypted datagrams to and from the application's transport with an internal relay; the block callbacks are driven through a small Objective-C block ABI shim.

The deprecated **Secure Transport** stack remains as a **DTLS 1.0** fallback (certificate auth), used when Network.framework is unavailable or when only DTLS 1.0 is requested. Secure Transport cannot select DTLS 1.2 on current macOS: requesting it through `SSLSetProtocolVersionMin`/`SSLSetProtocolVersionMax`/`SSLSetProtocolVersionEnabled` returns `errSSLBadConfiguration` (-9830). Both paths are exercised by macOS-guarded self-interop integration tests (DTLS 1.2 over Network.framework and DTLS 1.0 over Secure Transport).

## DTLS 1.3 cipher suites

The managed DTLS 1.3 engine negotiates the following AEAD cipher suites (RFC 9147 /
RFC 8446 appendix B.4), in this default preference order:

| Cipher suite | ID | Hash | Tag | Frameworks | Notes |
| --- | --- | --- | --- | --- | --- |
| `TLS_AES_128_GCM_SHA256` | 0x1301 | SHA-256 | 16 | all | Mandatory modern AEAD suite |
| `TLS_AES_256_GCM_SHA384` | 0x1302 | SHA-384 | 16 | all | Higher-strength AES-GCM suite |
| `TLS_AES_128_CCM_SHA256` | 0x1304 | SHA-256 | 16 | net8.0+ | AES-CCM; uses BCL `AesCcm` |
| `TLS_AES_128_CCM_8_SHA256` | 0x1305 | SHA-256 | 8 | net8.0+ | AES-CCM with a short (8-byte) tag |

The AES-CCM suites require the BCL `System.Security.Cryptography.AesCcm` primitive, which is
unavailable on `netstandard2.1`; they are only negotiable on .NET 8 or later. On
`netstandard2.1` only the two AES-GCM suites are supported.

`TLS_CHACHA20_POLY1305_SHA256` (0x1303) is intentionally **not** negotiated for DTLS 1.3.
DTLS 1.3 mandates record sequence-number encryption (RFC 9147 section 4.2.3), which for the
ChaCha20-Poly1305 suite requires a raw ChaCha20 keystream block that the BCL does not expose.
The suite remains defined internally but is excluded from negotiation.

Applications select or restrict suites with `DtlsOptions.CipherSuites`
(a `DtlsCipherSuite` preference/allow-list). An empty list (the default) negotiates all
suites supported on the current target framework in the order above. The client offers the
configured list (for external-PSK handshakes, only the SHA-256 suites, since the PSK binder
fixes the hash to SHA-256); the server picks by its own preference order intersected with the
client's offer and fails the handshake when there is no overlap.

DTLS 1.3 support is AEAD-only and does not include legacy CBC or MAC-then-encrypt cipher suites.

## DTLS 1.0 and DTLS 1.2 cipher suites

For DTLS 1.0 and DTLS 1.2, the native operating system stack determines which cipher suites, signature algorithms, protocol options, and policy restrictions are available.

Applications should treat DTLS 1.0 as deprecated and enable it only for legacy interoperability.

## Named groups

The intended named groups for managed DTLS 1.3 are:

| Named group | Notes |
| --- | --- |
| `secp256r1` | Intended supported NIST P-256 group |
| `secp384r1` | Intended supported NIST P-384 group |
| `secp521r1` | Intended supported NIST P-521 group |
| `X25519` | Intended where the target BCL and platform support it |

For DTLS 1.0 and DTLS 1.2, named group availability is determined by the native backend and operating system policy.

## Credential modes

| Credential mode | DTLS 1.0 | DTLS 1.2 | DTLS 1.3 | Notes |
| --- | --- | --- | --- | --- |
| X.509 ECDSA/RSA certificates | Native backend | Native backend | Managed engine with BCL X.509 and signatures | Certificate validation defaults to strict chain and identity checks |
| Pre-shared keys | Native backend where supported | Native backend where supported | Managed engine | PSK identity and key selection are provided by application callbacks |
| Raw Public Keys (RFC 7250) | Native backend where supported | Native backend where supported | Managed engine | RPK trust decisions are provided by application key-pinning callbacks |

## Connection ID

DTLS Connection ID from RFC 9146 is supported so a connection can remain associated with its cryptographic state when peer addressing changes and policy permits that behavior.

## Interoperability status

DTLS 1.0 and DTLS 1.2 are validated in CI against OpenSSL `s_server` and `s_client`.

DTLS 1.3 does not have mainstream native OpenSSL interop coverage because OpenSSL lacks DTLS 1.3 support, so correctness is validated through RFC 9147 vectors, self-interop, and optional wolfSSL interoperability testing.
