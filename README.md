# Dtls — DTLS for .NET

A cross-platform [DTLS](https://datatracker.ietf.org/doc/html/rfc9147) library for .NET that, like the BCL, uses the host operating system's cryptography. It supports **DTLS 1.0, 1.2, and 1.3** with a modern, allocation-conscious (`Span<T>`) datagram API.

> Status: under active development. Working and verified end to end today: the managed **DTLS 1.3** path (PSK, certificate, and raw-public-key auth) on Windows and Linux, the native **Windows Schannel DTLS 1.2** backend, the native **Linux OpenSSL DTLS 1.2** backend (certificate + PSK, including interop against the `openssl` CLI), and the native **macOS Network.framework DTLS 1.2** backend (certificate; verified on the macOS CI runner), with the deprecated **Secure Transport DTLS 1.0** stack as a fallback. See [`docs/`](docs/) for details.

## Why hybrid

No native OS DTLS stack supports DTLS 1.3 yet (OpenSSL, Schannel, and Apple all cap at DTLS 1.2). To deliver 1.3 everywhere *and* stay NativeAOT-compatible, this library uses a hybrid design:

| DTLS version | Engine | Crypto provider |
| ------------ | ------ | --------------- |
| 1.0, 1.2 | **Native OS stack** (P/Invoke) | OpenSSL (Linux) · Schannel (Windows) · Network.framework / Secure Transport (macOS) |
| 1.3 | **Managed C#** | BCL `System.Security.Cryptography` (delegates to OpenSSL / CNG / Apple) |

Delegating the legacy CBC-era 1.0/1.2 handshakes to hardened native stacks avoids hand-rolling the most dangerous (timing/padding-oracle prone) crypto, while the clean AEAD-only 1.3 path is implemented in managed, AOT-friendly code.

## Features

- DTLS **1.3** (managed; client and server) — working on Windows and Linux, with **PSK**, **X.509 certificate** (ECDSA/RSA-PSS), and **Raw Public Key** (RFC 7250) authentication.
- DTLS 1.3 cipher suites: **AES-128-GCM** and **AES-256-GCM** (all TFMs), plus **AES-128-CCM** and **AES-128-CCM-8** (net8+); selectable via `DtlsOptions.CipherSuites`. (ChaCha20-Poly1305 is not offered: the BCL has no raw ChaCha20 for DTLS 1.3 sequence-number encryption.)
- DTLS **1.2** on **Windows** via the native Schannel backend — working (client and server, certificate auth).
- DTLS **1.2** on **Linux** via the native OpenSSL backend — working (client and server, certificate + PSK), with verified interop against the `openssl` CLI (`s_server`/`s_client`).
- DTLS **1.2** on **macOS** via the native Network.framework backend — working (client and server, certificate auth), verified on the macOS CI runner. Network.framework owns its own UDP socket, so the backend bridges it to the library's `IDatagramTransport` through an internal loopback relay. The deprecated **Secure Transport** stack provides a **DTLS 1.0** fallback (Secure Transport cannot select DTLS 1.2 on current macOS).
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

## Versioning & packages

Versions come from [Nerdbank.GitVersioning](https://github.com/dotnet/Nerdbank.GitVersioning): `version.json` pins the `0.9` line and each commit gets a unique `0.9.{git-height}` version. Tag a release with `nbgv tag` (creating a `v0.9.x` tag) and push it.

Pushing a `v*` tag runs CI and, once green, publishes `Dtls` to this repo's **GitHub Packages** NuGet feed. The manual **`nuget`** workflow (Actions tab) then takes the latest package from that feed and publishes it to **nuget.org** via [trusted publishing](https://learn.microsoft.com/nuget/nuget-org/trusted-publishing) (OIDC — no stored API key), using the `release` environment.

First-time nuget.org setup (one-time, by a maintainer):

- Create a trusted publishing policy at [nuget.org/account/trustedpublishing](https://www.nuget.org/account/trustedpublishing): Repository Owner `marcschier`, Repository `dtls`, Workflow File `nuget.yml`, Environment `release`.
- Add a `NUGET_USER` secret (your nuget.org username, not email) to the `release` environment.

## Security

This is a security-protocol implementation; see [`docs/security.md`](docs/security.md) for the threat model and hardening notes. DTLS 1.0 is deprecated (RFC 8996) and is **off by default**.

## License

[MIT](LICENSE).
