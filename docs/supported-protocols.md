# Supported protocols

Dtls supports DTLS 1.0, DTLS 1.2, and DTLS 1.3 across Linux, Windows, and macOS with a hybrid native/managed architecture.

## Version and platform matrix

| DTLS version | Linux | Windows | macOS | Engine | Default |
| --- | --- | --- | --- | --- | --- |
| DTLS 1.0 | OpenSSL | Schannel/SSPI | Secure Transport | Native | Off by default; explicit opt-in required |
| DTLS 1.2 | OpenSSL | Schannel/SSPI | Network.framework | Native (managed fallback) | Enabled |
| DTLS 1.3 | Managed C# with BCL crypto | Managed C# with BCL crypto | Managed C# with BCL crypto | Managed | Enabled where policy allows |

OpenSSL, Schannel, and Apple Secure Transport / Network.framework do not currently provide a mainstream native DTLS 1.3 stack, so DTLS 1.3 is implemented in managed code and uses BCL cryptographic primitives backed by the operating system crypto provider.

For DTLS 1.2, the native operating-system stack is preferred on Linux, Windows, and macOS. On platforms where no native DTLS backend is available (for example Android and iOS), a fully managed DTLS 1.2 engine — implemented in C# on the same BCL primitives as the DTLS 1.3 engine — is used as the universal fallback. The public `DtlsClient`/`DtlsServer` API selects the managed DTLS 1.2 engine automatically when `NativeDtlsBackend.ForCurrentPlatform()` returns no backend.

The library targets `netstandard2.0`, `netstandard2.1`, `net8.0`, `net9.0`, and `net10.0`, and additionally builds the mobile target frameworks `net10.0-android` and `net10.0-ios` (validated build-only in CI). On iOS the BCL AES-CCM primitive is unavailable, so the AES-CCM cipher suites are compiled out there (AES-GCM remains the default AEAD); Android retains the full suite set. Both mobile platforms run DTLS through the managed DTLS 1.2 engine and the managed DTLS 1.3 engine. `netstandard2.0` is a compile/API-compatibility target only (for .NET Framework 4.6.1+, Unity, Mono): its BCL has no managed AEAD or `ECDiffieHellman`, so the wire codecs, value types, and datagram transports run but the handshake throws `PlatformNotSupportedException` (see the cipher-suite note below).

### Version negotiation and DTLS 1.2 downgrade

When the configured version range spans both versions (`MinimumVersion = Dtls12`,
`MaximumVersion = Dtls13` — the default) and certificate authentication is used, the managed client
offers **both** DTLS 1.3 and DTLS 1.2 in a single ClientHello (RFC 8446 section 4.2.1): the
`supported_versions` extension lists DTLS 1.3 then DTLS 1.2, and the cipher-suite list and
extensions include the DTLS 1.2 certificate suites alongside the DTLS 1.3 suites and `key_share`. A
DTLS 1.3 peer selects 1.3 and the managed 1.3 engine completes the handshake; a DTLS 1.2 peer
selects 1.2 (answering with a HelloVerifyRequest or its ServerHello flight) and the handshake is
completed by the managed DTLS 1.2 engine, reusing the same transport without a restart.

This lets a client at the default range complete a handshake with a DTLS 1.2-only managed peer
without explicit configuration. Note that strict native DTLS 1.2-only servers (for example Schannel)
may reject a ClientHello that carries the DTLS 1.3 `supported_versions`/`key_share` constructs; to
interoperate with such a server, set `MaximumVersion = Dtls12` so a plain DTLS 1.2 ClientHello is
sent. External-PSK handshakes do not downgrade (they pin the offered version).

### macOS native backend (Network.framework, Secure Transport fallback)

On macOS the native DTLS path prefers Apple's modern **Network.framework**, whose secure-UDP transport negotiates **DTLS 1.2** (verified on the macOS CI runner, certificate auth). Because Network.framework owns its own UDP socket and exposes an asynchronous, Objective-C block-based API, the backend runs the DTLS endpoint over a private loopback socket and bridges the encrypted datagrams to and from the application's transport with an internal relay; the block callbacks are driven through a small Objective-C block ABI shim.

The deprecated **Secure Transport** stack remains as a **DTLS 1.0** fallback (certificate auth), used when Network.framework is unavailable or when only DTLS 1.0 is requested. Secure Transport cannot select DTLS 1.2 on current macOS: requesting it through `SSLSetProtocolVersionMin`/`SSLSetProtocolVersionMax`/`SSLSetProtocolVersionEnabled` returns `errSSLBadConfiguration` (-9830). Both paths are exercised by macOS-guarded self-interop integration tests (DTLS 1.2 over Network.framework and DTLS 1.0 over Secure Transport).

### Managed DTLS 1.2 fallback engine

Where no native DTLS backend exists, a managed DTLS 1.2 engine (RFC 6347 + TLS 1.2, RFC 5246) provides the protocol. It is a second full protocol implementation alongside the managed DTLS 1.3 engine and shares its building blocks: the BCL AEAD ciphers (AES-GCM, and AES-CCM on .NET 8+), `ECDiffieHellman` for ECDHE over the NIST P-curves, the DTLS handshake header and message reassembler, and the flight transceiver (retransmission on loss). DTLS 1.2 differs from 1.3 in its record layer (the epoch and 48-bit sequence number travel in the cleartext record header, with an explicit 8-byte AEAD nonce per record and no sequence-number encryption), its key schedule (the TLS 1.2 PRF with `P_SHA256`/`P_SHA384`, master secret, key block, and Finished `verify_data`), and its multi-flight, plaintext handshake terminated by ChangeCipherSpec and a protected Finished.

The managed DTLS 1.2 engine supports:

- **Certificate-authenticated ECDHE** (RFC 5289): `TLS_ECDHE_ECDSA_*` and `TLS_ECDHE_RSA_*` AES-GCM (and AES-CCM on .NET 8+) suites. The server signs its ephemeral ECDHE parameters; the client validates the certificate with `DtlsClientOptions.RemoteCertificateValidation`. TLS 1.2 signatures use ECDSA (DER-encoded) or RSASSA-PKCS1-v1_5 — distinct from the RSA-PSS used by TLS 1.3.
- **External pre-shared keys** (RFC 4279 / RFC 5489): plain PSK and ECDHE_PSK (forward-secret) suites, selected by `DtlsClientOptions.PskCallback` / `DtlsServerOptions.PskCallback`.
- **Mutual (client-certificate) authentication** via `DtlsServerOptions.RequireClientCertificate` and the client's `ClientCertificates`.
- **`extended_master_secret`** (RFC 7627), which is offered and required by both roles, binding the master secret to the handshake transcript.
- **HelloVerifyRequest** (RFC 6347): the server returns a stateless, HMAC-authenticated cookie so the client proves return-routability of its source address before the server commits handshake state.

The managed DTLS 1.2 engine compiles on every target framework but, like the managed DTLS 1.3 engine, runs only where the BCL provides `ECDiffieHellman.DeriveRawSecretAgreement` and the ECDSA DER signature overloads (.NET 8 or later).

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
`netstandard2.1` only the two AES-GCM suites are supported. On `netstandard2.0` the BCL has no
`AesGcm`/`AesCcm` (nor `ECDiffieHellman`) at all, so no suite is negotiable and the handshake
throws `PlatformNotSupportedException`; that target exists for compile/API compatibility only.

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
| X.509 ECDSA/RSA certificates | Native backend | Native backend, or managed engine (fallback) | Managed engine with BCL X.509 and signatures | Certificate validation defaults to strict chain and identity checks |
| Pre-shared keys | Native backend where supported | Native backend, or managed engine (plain PSK and ECDHE_PSK) | Managed engine | PSK identity and key selection are provided by application callbacks |
| Raw Public Keys (RFC 7250) | Native backend where supported | Native backend where supported | Managed engine | RPK trust decisions are provided by application key-pinning callbacks |

## Connection ID

DTLS Connection ID (RFC 9146) is negotiated by the managed DTLS 1.3 engine so a connection can remain associated with its cryptographic state when the peer's address changes. It is opt-in: set `DtlsOptions.UseConnectionId` on both endpoints. When both peers enable it, each side generates a CID that the peer places on every protected record it sends (the CID is part of the AEAD additional data). If either side does not request a CID, the handshake proceeds without one. The native DTLS 1.0/1.2 backends do not use this setting.

## Mutual (client-certificate) authentication

The managed DTLS 1.3 certificate path supports mutual authentication (RFC 8446 section 4.3.2). Set `DtlsServerOptions.RequireClientCertificate` to make the server send a CertificateRequest; the client answers with its Certificate and CertificateVerify chosen from `DtlsClientOptions.ClientCertificates`. The server validates the presented certificate with `DtlsServerOptions.ClientCertificateValidation` and fails the handshake (alert `handshake_failure`) when a required certificate is absent. The client CertificateVerify signs the `"TLS 1.3, client CertificateVerify"` context string, distinct from the server's.

## HelloRetryRequest (stateless anti-DoS cookie)

Set `DtlsServerOptions.EnableStatelessRetry` to make the managed DTLS 1.3 certificate server answer the first ClientHello with a HelloRetryRequest carrying an authenticated cookie (RFC 9147 section 5.1 / RFC 8446 section 4.1.4). This forces the client to prove return-routability of its source address before the server commits handshake state, mitigating denial-of-service amplification. The cookie is an HMAC over the first ClientHello transcript hash and the selected group, so the server reconstructs the post-retry transcript from the returned cookie. When the client advertised an additional (EC)DHE group without a key_share, the HelloRetryRequest also corrects the group, and the client regenerates its key_share for it. The client resends a second ClientHello echoing the cookie, and both sides fold the synthetic `message_hash` of the first ClientHello into the transcript. The external-PSK path does not emit a HelloRetryRequest.

## Handshake reliability (retransmission and ACKs)

The managed DTLS 1.3 handshake is resilient to datagram loss and duplication. Each flight is driven through a flight transceiver that retransmits the current flight when the expected next flight does not arrive within `DtlsOptions.HandshakeRetransmissionTimeout` (RFC 9147 section 5.8); the timeout doubles on each retry, capped, up to `DtlsOptions.MaxHandshakeRetransmissions` attempts. Retransmitted peer flights are de-duplicated so they are never processed twice, and a retransmitted peer flight signals that the local reply was lost and is resent. The client's final flight is acknowledged with an ACK record (RFC 9147 section 7), which the client acknowledges in turn, so the handshake reliably completes on both sides without lingering on the lossless path.

Handshake messages larger than the transport MTU (`IDatagramTransport.MaxDatagramSize`) are fragmented across datagrams and reassembled (RFC 9147 section 5.5). This covers both the protected flights (the Certificate flight is the common case) and the plaintext hellos; a fragmented ClientHello is reassembled by the server before it is routed to the managed engine. Reassembled messages are bounded by `DtlsOptions.MaxHandshakeMessageSize`.

## Key update

The managed DTLS 1.3 engine supports post-handshake key update (RFC 8446 section 4.6.3): call `DtlsConnection.UpdateKeyAsync(requestPeerUpdate)` to rotate the sending keys to the next application traffic generation (incrementing the epoch). With `requestPeerUpdate: true`, the peer also updates and returns a KeyUpdate. Inbound KeyUpdate messages are handled automatically. KeyUpdate is a DTLS 1.3 feature; the native 1.0/1.2 backends throw `NotSupportedException`.

## Interoperability status

DTLS 1.0 and DTLS 1.2 are validated in CI against OpenSSL `s_server` and `s_client`.

The managed DTLS 1.2 engine is validated against the native OpenSSL DTLS 1.2 backend in CI, in both
directions (managed client to OpenSSL server, and OpenSSL client to managed server) and for both
certificate and PSK authentication. This cross-implementation testing exercises the real `libssl`
wire format, including the HelloVerifyRequest-less server flow, the extended_master_secret and
renegotiation_info (RFC 5746) extensions, and the advisory record-layer legacy_version that DTLS
receivers ignore (RFC 6347 / RFC 9147).

DTLS 1.3 does not have mainstream native OpenSSL interop coverage because OpenSSL lacks DTLS 1.3 support, so correctness is validated through RFC 9147 vectors, self-interop, and optional wolfSSL interoperability testing.
