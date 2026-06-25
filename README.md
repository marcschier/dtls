# Dtls — DTLS for .NET

[![CI](https://github.com/marcschier/dtls/actions/workflows/ci.yml/badge.svg?branch=main)](https://github.com/marcschier/dtls/actions/workflows/ci.yml) [![NativeAOT](https://github.com/marcschier/dtls/actions/workflows/aot.yml/badge.svg?branch=main)](https://github.com/marcschier/dtls/actions/workflows/aot.yml) [![NuGet](https://img.shields.io/nuget/v/DtlsSharp?logo=nuget&label=NuGet)](https://www.nuget.org/packages/DtlsSharp) [![GitHub Packages](https://img.shields.io/badge/GitHub%20Packages-DtlsSharp-2088FF?logo=github&logoColor=white)](https://github.com/marcschier/dtls/pkgs/nuget/DtlsSharp)

A cross-platform [DTLS](https://datatracker.ietf.org/doc/html/rfc9147) library for .NET that, like the BCL, uses the host operating system's cryptography. It supports **DTLS 1.0, 1.2, and 1.3** with a modern, allocation-conscious (`Span<T>`) datagram API.

> Status: actively developed and CI-green on Linux, Windows, and macOS. Working and verified end to end: the managed **DTLS 1.3** engine (PSK, certificate, raw-public-key, mutual auth); the managed **DTLS 1.2** engine (certificate, PSK, ECDHE-PSK, raw-public-key, mutual auth) used as the universal fallback where no native stack exists; the native **Schannel** (Windows), **OpenSSL** (Linux), and **Network.framework** (macOS) DTLS 1.2 backends, with the deprecated **Secure Transport DTLS 1.0** stack as a fallback. The managed 1.2 engine is interop-tested against both OpenSSL and Schannel in CI (both directions), and the library negotiates a **DTLS 1.3 → 1.2 downgrade** automatically. See the [documentation](#-documentation) for details.

## 🧩 Why hybrid

No native OS DTLS stack supports DTLS 1.3 yet (OpenSSL, Schannel, and Apple all cap at DTLS 1.2). To deliver 1.3 everywhere *and* stay NativeAOT-compatible, this library uses a hybrid design:

| DTLS version | Engine | Crypto provider |
| ------------ | ------ | --------------- |
| 1.0, 1.2 | **Native OS stack** (P/Invoke), or the **managed C# engine** where no native stack exists (iOS, Android) | OpenSSL (Linux) · Schannel (Windows) · Network.framework / Secure Transport (macOS) · BCL (managed fallback) |
| 1.3 | **Managed C#** | BCL `System.Security.Cryptography` (delegates to OpenSSL / CNG / Apple) |

Delegating the legacy CBC-era 1.0/1.2 handshakes to hardened native stacks avoids hand-rolling the most dangerous (timing/padding-oracle prone) crypto, while the clean AEAD-only 1.3 path — and the AEAD-only managed 1.2 fallback for platforms without a native stack — is implemented in managed, AOT-friendly code.

## ✨ Features

- DTLS **1.3** (managed; client and server) with **PSK**, **X.509 certificate** (ECDSA / RSA-PSS), **Raw Public Key** (RFC 7250), and **mutual** authentication.
- Managed DTLS **1.2** engine (client and server) — the universal fallback where no native stack exists (**iOS, Android**) — with **certificate** (ECDSA / RSA-PKCS#1), **PSK** and forward-secret **ECDHE-PSK**, **Raw Public Key**, and **mutual** authentication, plus `extended_master_secret` (RFC 7627) and the stateless HelloVerifyRequest cookie. Interop-tested in CI against **OpenSSL** and **Schannel** in both directions.
- Automatic **DTLS 1.3 → 1.2 downgrade**: at the default version range the client offers both and completes on whichever the peer selects, over the same transport.
- Native DTLS **1.2** backends — **Schannel** (Windows), **OpenSSL** (Linux), and **Network.framework** (macOS) — preferred where present; the deprecated **Secure Transport** stack provides a DTLS **1.0** fallback on macOS.
- AEAD cipher suites: **AES-128-GCM** and **AES-256-GCM** (all TFMs), plus **AES-128-CCM** and **AES-128-CCM-8** (net8+; unavailable on iOS, where AES-GCM remains the default). Selectable via `DtlsOptions.CipherSuites`. (ChaCha20-Poly1305 is not offered: the BCL has no raw ChaCha20 for DTLS 1.3 sequence-number encryption.)
- Modern, allocation-conscious **`Span<T>`** API; transport-agnostic with a built-in UDP `Socket` adapter and an in-memory loopback transport.
- Targets **netstandard2.1, net8.0, net9.0, net10.0** (plus opt-in **`net10.0-android`** / **`net10.0-ios`**); **NativeAOT-compatible** on net10.

## 📚 Documentation

- [Usage](docs/usage.md) — getting started: client/server handshakes, options, and the datagram transport API.
- [Architecture](docs/architecture.md) — the hybrid native/managed design and how the engines and backends fit together.
- [Supported protocols](docs/supported-protocols.md) — version/platform matrix, cipher suites, credential modes, and interop status.
- [Security model](docs/security.md) — threat model and hardening notes.
- [NativeAOT & trimming](docs/aot.md) — AOT/trimming compatibility and guidance.

## Project layout

```
src/      the Dtls library
tests/    unit, integration, and OpenSSL/Schannel interop tests
samples/  UDP echo client/server
docs/     usage, architecture, security model, supported protocols, AOT
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

## 🔒 Security

This is a security-protocol implementation; see [`docs/security.md`](docs/security.md) for the threat model and hardening notes. DTLS 1.0 is deprecated (RFC 8996) and is **off by default**.

## License

[MIT](LICENSE).
