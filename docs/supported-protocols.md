# Supported protocols

Dtls supports DTLS 1.0, DTLS 1.2, and DTLS 1.3 across Linux, Windows, and macOS with a hybrid native/managed architecture.

## Version and platform matrix

| DTLS version | Linux | Windows | macOS | Engine | Default |
| --- | --- | --- | --- | --- | --- |
| DTLS 1.0 | OpenSSL | Schannel/SSPI | Secure Transport | Native | Off by default; explicit opt-in required |
| DTLS 1.2 | OpenSSL | Schannel/SSPI | Secure Transport | Native | Enabled |
| DTLS 1.3 | Managed C# with BCL crypto | Managed C# with BCL crypto | Managed C# with BCL crypto | Managed | Enabled where policy allows |

OpenSSL, Schannel, and Apple Secure Transport / Network.framework do not currently provide a mainstream native DTLS 1.3 stack, so DTLS 1.3 is implemented in managed code and uses BCL cryptographic primitives backed by the operating system crypto provider.

## DTLS 1.3 cipher suites

The intended DTLS 1.3 AEAD cipher suites are:

| Cipher suite | Notes |
| --- | --- |
| `TLS_AES_128_GCM_SHA256` | Required modern AEAD suite |
| `TLS_AES_256_GCM_SHA384` | Higher-strength AES-GCM suite |
| `TLS_CHACHA20_POLY1305_SHA256` | AEAD suite for platforms and CPUs where ChaCha20-Poly1305 is preferred or available |

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
