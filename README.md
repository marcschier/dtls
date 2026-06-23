# Dtls — DTLS for .NET

A cross-platform [DTLS](https://datatracker.ietf.org/doc/html/rfc9147) library for .NET that, like the BCL, uses the host operating system's cryptography. It supports **DTLS 1.0, 1.2, and 1.3** with a modern, allocation-conscious (`Span<T>`) datagram API.

> Status: under active development. Working and verified end to end today: the managed **DTLS 1.3** path (PSK, certificate, and raw-public-key auth) on Windows and Linux, the native **Windows Schannel DTLS 1.2** backend, and the native **Linux OpenSSL DTLS 1.2** backend (certificate + PSK, including interop against the `openssl` CLI). The macOS Secure Transport backend is not yet implemented. See [`docs/`](docs/) for details.

## Why hybrid

No native OS DTLS stack supports DTLS 1.3 yet (OpenSSL, Schannel, and Apple all cap at DTLS 1.2). To deliver 1.3 everywhere *and* stay NativeAOT-compatible, this library uses a hybrid design:

| DTLS version | Engine | Crypto provider |
| ------------ | ------ | --------------- |
| 1.0, 1.2 | **Native OS stack** (P/Invoke) | OpenSSL (Linux) · Schannel (Windows) · Secure Transport (macOS) |
| 1.3 | **Managed C#** | BCL `System.Security.Cryptography` (delegates to OpenSSL / CNG / Apple) |

Delegating the legacy CBC-era 1.0/1.2 handshakes to hardened native stacks avoids hand-rolling the most dangerous (timing/padding-oracle prone) crypto, while the clean AEAD-only 1.3 path is implemented in managed, AOT-friendly code.

## Features

- DTLS **1.3** (managed; client and server) — working on Windows and Linux, with **PSK**, **X.509 certificate** (ECDSA/RSA-PSS), and **Raw Public Key** (RFC 7250) authentication.
- DTLS **1.2** on **Windows** via the native Schannel backend — working (client and server, certificate auth).
- DTLS **1.2** on **Linux** via the native OpenSSL backend — working (client and server, certificate + PSK), with verified interop against the `openssl` CLI (`s_server`/`s_client`).
- DTLS **1.0/1.2** on macOS (Secure Transport) — planned (honest stub today).
- Transport-agnostic datagram API with a built-in UDP `Socket` adapter and an in-memory loopback transport.
- Targets **netstandard2.1, net8.0, net9.0, net10.0**; **NativeAOT-compatible** on net10, verified on Windows and Linux.

## Project layout

```
src/      the Dtls library
tests/    unit, integration, and OpenSSL-interop tests
samples/  UDP echo client/server
docs/     architecture, security model, supported protocols
```

## Build & test

```bash
dotnet build
dotnet test
```

The native backends require their host OS: the Schannel DTLS 1.2 backend and its tests run on Windows; the OpenSSL DTLS 1.2 backend and its tests run on Linux. On a Windows machine, build and test the Linux side with WSL:

```bash
# from WSL (the repo is visible at /mnt/<drive>/...)
./eng/wsl-verify.sh
```

Tests that need a specific OS no-op elsewhere, so the suite is green on every platform.

## Security

This is a security-protocol implementation; see [`docs/security.md`](docs/security.md) for the threat model and hardening notes. DTLS 1.0 is deprecated (RFC 8996) and is **off by default**.

## License

[MIT](LICENSE).
