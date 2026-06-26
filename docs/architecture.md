# Dtls architecture

Dtls is a cross-platform DTLS library for .NET that supports DTLS 1.0, DTLS 1.2, and DTLS 1.3 while following the .NET Base Class Library philosophy of using the host operating system's cryptography instead of shipping an independent cryptographic stack.

## Goals

The library is designed to provide client and server roles, a modern allocation-conscious API based on `Span<T>`, `ReadOnlySpan<T>`, `Memory<T>`, and `ReadOnlyMemory<T>`, and a datagram/message-oriented programming model that matches DTLS rather than exposing a stream abstraction.

The target frameworks are `netstandard2.0`, `netstandard2.1`, `net8.0`, `net9.0`, and `net10.0`; the `net10.0` target is intended to be NativeAOT-compatible. `netstandard2.0` is a compile/API-compatibility target (for .NET Framework 4.6.1+, Unity, and Mono): it relies on polyfill packages (`System.Memory`, `System.Threading.Tasks.Extensions`, `Microsoft.Bcl.HashCode`) plus small internal `CryptographicOperations` and secure-random shims, and because that BCL ships no `AesGcm`/`AesCcm`/`ECDiffieHellman`, the cryptographic handshake throws `PlatformNotSupportedException` while the wire codecs, value types, and transports still run.

The repository layout is intentionally simple: `src/` contains the library, `tests/` contains automated tests, `samples/` contains runnable examples, and `docs/` contains design and usage documentation.

## Hybrid protocol engine

The central architectural decision is a hybrid design: DTLS 1.0 and DTLS 1.2 are delegated to native operating system DTLS implementations, while DTLS 1.3 is implemented in managed C# using BCL cryptographic primitives.

This split exists because, as verified in June 2026, mainstream host DTLS stacks do not expose DTLS 1.3 support: OpenSSL on Linux, Schannel/SSPI on Windows, and Apple Secure Transport / Network.framework on macOS all cap at DTLS 1.2 for native DTLS.

DTLS 1.0 and DTLS 1.2 include legacy CBC-era MAC-then-encrypt cipher suites where padding-oracle and timing behavior are high-risk implementation areas, so Dtls delegates those versions to hardened native stacks that have received extensive platform and ecosystem scrutiny.

DTLS 1.3 is AEAD-only, has a cleaner key schedule, removes the legacy CBC record protection surface, and is implemented in managed code so every supported platform can offer DTLS 1.3 even when the host DTLS stack cannot.

## Platform backends

On Linux, the native backend for DTLS 1.0 and DTLS 1.2 is OpenSSL accessed through P/Invoke.

On Windows, the native backend for DTLS 1.0 and DTLS 1.2 is Schannel through SSPI accessed through P/Invoke.

On macOS, the native backend for DTLS 1.0 and DTLS 1.2 is Secure Transport accessed through P/Invoke.

The managed DTLS 1.3 engine uses `System.Security.Cryptography` primitives such as AES-GCM, ChaCha20-Poly1305, ECDHE, HKDF, signatures, and X.509 handling; those BCL primitives in turn use the operating system cryptography providers on each platform.

## Version routing

On the server side, a small managed pre-parser peeks at the first ClientHello and inspects the `supported_versions` extension before allocating full handshake state.

If the ClientHello negotiates DTLS 1.3, the connection is routed to the managed DTLS 1.3 engine; if it negotiates DTLS 1.2 or earlier, the connection is routed to the native backend for that platform.

On the client side, version policy is explicit per connection so the correct engine can be selected up front.

When a client policy requests "maximum DTLS 1.3 with DTLS 1.2 fallback" and the peer selects DTLS 1.2 or earlier, the connection is restarted against the native backend rather than switching engines mid-handshake.

## Public API shape

The public API is planned to be transport-agnostic at its core, with a built-in UDP socket adapter for common deployments.

Planned API concepts include an `IDatagramTransport` abstraction, `DtlsClient`, `DtlsServer`, and `DtlsConnection` types, with asynchronous datagram-oriented `SendAsync` and `ReceiveAsync` operations that accept cancellation tokens.

The API is intended to support X.509 certificates using ECDSA or RSA, pre-shared keys, Raw Public Keys as defined by RFC 7250, and DTLS Connection ID as defined by RFC 9146.

## Interoperability and validation

DTLS 1.0 and DTLS 1.2 interoperability is validated in CI against the OpenSSL reference tools `s_server` and `s_client`.

DTLS 1.3 does not currently have a mainstream native reference implementation in OpenSSL, so validation relies on RFC 9147 test vectors, self-interop testing, and optional interop testing against implementations such as wolfSSL where available.
