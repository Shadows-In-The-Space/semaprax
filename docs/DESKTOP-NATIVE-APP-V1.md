# Private native desktop application v1

Audience: maintainers, host integrators, and compiler contributors.

Status: the bounded macOS and Windows package/runtime paths are hosted green:
macOS in [run 31338834586, job 93309086230](https://github.com/wavect/semaprax/actions/runs/31338834586/job/93309086230)
and Windows in [run 31343897595, job 93322134480](https://github.com/wavect/semaprax/actions/runs/31343897595/job/93322134480).

This milestone packages one exact graph-derived callable-v3 owned-identity
provider with the unpublished native host. It requires
`unstable-desktop-app-harness`; it adds no public compiler, admission or
ownership surface.

## Artifacts

- macOS: `SemapraxPrivate.app`, with a native executable in `Contents/MacOS`,
  the exact provider and descriptor in `Contents/Resources`, and a canonical
  `CFBundlePackageType=APPL` property list.
- Windows: a portable application directory containing a PE executable, PE
  provider DLL, exact descriptor, and an external `asInvoker` application
  manifest.

When executed, each packaged process admits the descriptor and provider through
the existing root-provenance loader, constructs the OS-seeded receipt authority
and ledger, executes two owned calls with payloads 41 and 43, rotates the
authoritative generation between them, and requires byte-identical replay of
the first committed result. That path is proven in hosted CI on both platforms.
Success prints one exact platform-tagged line.

## Evidence contract

The scripts pin and check Rust 1.97.1, platform Clang/linker identities and the
selected SDK/build/import-library identity. They run Cargo offline and build
the provider, descriptor and application twice in independent target
directories. Packaged executable bytes must match under that exact toolchain;
this does not claim reproducibility across toolchains or SDKs.
The macOS dylib carries the stable package-relative
`@rpath/SemapraxPrivateProvider.dylib` install identity rather than a build
path. Its emitted build-version command is checked against the pinned Apple ld,
SDK build, and deployment target. On Windows, import-library identity means the
canonical Visual Studio 18 product line plus exact MSVC/linker/SDK versions,
canonical versioned roots with every path component proven non-reparse, exact
archive names, and COFF archive signatures; ambient `LIB` is replaced and the
provider links only explicit absolute archives under `/nodefaultlib`.
The hosted Windows image has presented two linker file revisions under the
same pinned MSVC tools version. The lock admits only those two exact revisions;
each package run still asserts its observed linker file and banner identities
and checks reproducibility within that one observed toolchain.
The macOS Rust link disables path-dependent linker signing, canonicalizes the
single `LC_UUID`, assembles two complete application bundles, then applies a
timestamp-free ad-hoc signature with the fixed identifier
`semaprax.private.desktop.v1` to each bundle. Their complete signed inventories
must compare byte-for-byte, and `codesign --verify --strict` must accept both
independent bundles and the packaged copy. This uses no distribution identity
or signing credential.

The scripts require strict C11 warnings, `-O2`, exact native Mach-O or PE/COFF
architecture and file kinds, closed load/import and export inventories, no
build-local load paths, an exact package inventory, and the effective Windows
`asInvoker` manifest. Runtime evidence additionally requires successful
descriptor-v3 admission, two authenticated owned receipt commits,
refreshed-owner reuse, exact replay, and an unpoisoned host. They reject an
existing or linked caller-selected output directory and perform no network
access. macOS uses only the deterministic ad-hoc signature above.

CI source locks require both platform commands to remain in the ordinary
macOS/Windows matrix. Hosted runtime evidence counts per platform only after
that hosted job is green.

## Explicit nonclaims

This v1 engine package is a headless application-process and packaging
milestone. It does not itself provide a window or lifecycle UI; the separate
private [native desktop UI v1](DESKTOP-NATIVE-UI-V1.md) consumes it without
expanding the engine API. Neither tranche provides SwiftUI, WinUI, menus,
installers, distribution code signing/notarization, Store packaging,
auto-update, sandbox entitlements, general SEMAPRAX application syntax, or public native resource
admission. The engine covers one direct-trivial owned identity only;
`SPX-B104` remains closed.
