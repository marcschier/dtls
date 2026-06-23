# Dtls security model

Dtls is designed for a network threat model where an attacker can observe, inject, drop, reorder, duplicate, and replay datagrams, and can attempt amplification and memory-exhaustion denial of service during handshake processing.

## Cryptographic boundary

Dtls does not implement custom cryptographic primitives.

All AEAD, KDF, ECDHE, signature, and X.509 operations are performed through `System.Security.Cryptography`, which delegates to host cryptographic providers such as OpenSSL, CNG, and Apple cryptography services as appropriate for the platform.

For DTLS 1.0 and DTLS 1.2, Dtls delegates the protocol engine to the host native DTLS stack because legacy CBC-era MAC-then-encrypt cipher suites are the most dangerous part of a DTLS implementation to reproduce correctly.

For DTLS 1.3, Dtls implements the protocol in managed C# because DTLS 1.3 is AEAD-only, has a cleaner key schedule, and is not exposed by the mainstream native DTLS stacks on supported platforms.

## Constant-time and key lifetime practices

Secret-dependent equality checks use `CryptographicOperations.FixedTimeEquals`.

Temporary key material and derived secrets are zeroed with `CryptographicOperations.ZeroMemory` as soon as their lifetime ends.

The design avoids reflection, dynamic code generation, and other runtime mechanisms that would complicate trimming, NativeAOT, and security review.

## Replay and record protection

Dtls maintains an anti-replay sliding window per epoch so reordered datagrams can be accepted while duplicated or replayed records are rejected.

For DTLS 1.3, record-number encryption is part of the managed record layer design.

DTLS Connection ID from RFC 9146 is supported so connections can survive peer address changes where policy allows it.

## Denial-of-service controls

The server design performs stateless cookie exchange before allocating full handshake state: DTLS 1.3 uses HelloRetryRequest cookies, while native DTLS 1.0 and DTLS 1.2 backends use the platform-supported HelloVerifyRequest path.

Handshake message size, fragment count, and reassembly buffer usage are strictly capped to prevent memory exhaustion from fragmented or malicious handshake traffic.

Retransmission timers are bounded so packet loss recovery does not create unbounded work or unbounded amplification.

The managed server pre-parser only inspects enough of the first ClientHello to route the connection to the DTLS 1.3 engine or the native DTLS 1.0/1.2 backend.

## Version policy

DTLS 1.0 is deprecated by RFC 8996 and is off by default.

Applications that need DTLS 1.0 for legacy interoperability must explicitly opt in through version policy.

DTLS 1.2 and DTLS 1.3 are the intended default protocol families, with DTLS 1.3 preferred where both peers support it.

## Authentication and validation

Certificate validation defaults to strict chain validation and endpoint identity checks.

Applications using pre-shared keys provide PSK identity and key selection through user callbacks.

Applications using Raw Public Keys provide key pinning and acceptance decisions through user callbacks.

Callback-based authentication decisions are part of the trust boundary and should avoid blocking operations, shared mutable state, and secret-dependent timing behavior where possible.

## Operational guidance

Use DTLS 1.3 when possible because it avoids legacy CBC record protection and provides the most consistent cross-platform behavior in Dtls.

Enable DTLS 1.0 only for a documented legacy interoperability requirement, and isolate such endpoints with narrow network access and explicit monitoring.

Keep the operating system cryptography stack current because DTLS 1.0 and DTLS 1.2 security properties depend on the host native DTLS implementation.
