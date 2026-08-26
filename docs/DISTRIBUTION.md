# Distribution and supply-chain controls

AgentShield produces a deterministically repackaged Linux archive containing the native CLI,
the Java desktop JAR, baseline policies, user documentation, a CycloneDX 1.5
source-input inventory in CycloneDX 1.5 format, and an in-toto build-metadata statement. The metadata statement is useful
for artifact traceability but deliberately does not claim a SLSA level or a
trusted external signature.

Run `make deterministic-package` on Linux with a JDK 17, C/C++ toolchain, Python 3,
and OpenSSL 3 development headers. The target creates the archive twice and
requires byte-for-byte equality while reusing the same build outputs. This checks
deterministic packaging, not independently reproducible compilation. `make verify-dist`
checks its bound SHA-256 entry, single safe top-level root, required content,
regular-file types, safe paths and modes, and absence of links or special files.
CI repeats package verification under a restrictive `umask 077`; archive
directory permissions are normalized to `0755` and never inherited from the builder.

The primary end-user installer is a Debian package containing the native monitor,
desktop console, application-menu shortcut, scalable icon, policies, documentation,
and license. Build and verify it with:

```bash
make verify-deb
```

Install with `sudo apt install ./build/dist/agentshield_*.deb` and remove with
`sudo apt remove agentshield`. Removal preserves user-created audit logs and policies.
The helper scripts `scripts/install-package.sh` and `scripts/uninstall-package.sh`
provide the same guided flow.

The CMake build additionally supports `.tar.gz` and Debian packages through CPack:

```bash
cmake -S . -B build-release -DCMAKE_BUILD_TYPE=Release
cmake --build build-release --parallel
cpack --config build-release/CPackConfig.cmake
```

Package consumers should verify the adjacent `.sha256` file before extraction.
Release publishing and signing are separate, explicitly authorized operations;
local build metadata is not a substitute for a signature issued by a protected
CI identity.

The generated `agentshield-source.cdx.json` is explicitly a source-input inventory.
It lists source and policy inputs by SHA-256 plus declared OpenSSL and Java
requirements; it is not a complete runtime/artifact SBOM or a vulnerability
scan. A release pipeline should add resolved ELF dependencies and package-manager
identifiers while preserving this inventory.
