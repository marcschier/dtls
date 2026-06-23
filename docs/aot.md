# NativeAOT and trimming

Dtls targets NativeAOT compatibility on `net10.0` and sets `IsAotCompatible=true` for that target.

## Compatibility goals

The managed DTLS 1.3 implementation is designed to be trim-safe, NativeAOT-friendly, and free of runtime code generation.

The public API is planned around static types, explicit options, and callback delegates rather than reflection-based activation or dynamic dispatch by string.

## Native interop

Native DTLS 1.0 and DTLS 1.2 backends use P/Invoke to call the host operating system stack.

On `net8.0` and later targets, interop declarations use `[LibraryImport]` so marshalling code is source-generated.

On `netstandard2.1`, interop declarations use `[DllImport]` because source-generated `[LibraryImport]` is not available for that target.

Native callbacks use `[UnmanagedCallersOnly]` where supported so callback entry points are explicit and compatible with AOT constraints.

## Reflection and dynamic code

Dtls does not rely on reflection or dynamic code generation for protocol processing, cryptographic operations, or native backend selection.

The managed DTLS 1.3 implementation uses BCL cryptographic APIs directly and avoids patterns that require runtime code emission.

This design keeps the library trim-safe and reduces the amount of linker configuration required by applications.

## Validation

CI publishes the samples with `PublishAot=true` on each supported operating system and runs a smoke handshake to verify that NativeAOT publishing and runtime protocol startup both work.

The AOT smoke coverage is in addition to normal unit, protocol, and interoperability validation.

## Application guidance

Applications should prefer the `net10.0` target when NativeAOT is required.

Applications using callbacks for certificate validation, PSK selection, or Raw Public Key pinning should keep those callbacks statically reachable and avoid reflection-only discovery.

Applications should test their published AOT binary on the same operating system family used in production because DTLS 1.0 and DTLS 1.2 native backend behavior depends on the host platform.
