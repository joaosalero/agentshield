# Platform support

AgentShield 0.1 is a Linux runtime-security preview. Platform claims are kept
narrow because process inspection and containment semantics differ materially
between kernels.

| Platform | Observation | Policy gate | Containment | Desktop |
|---|---|---|---|---|
| Linux x86-64, kernel 6.x | Supported | Supported | `rlimit`, process groups; delegated cgroup v2 optional | Supported with JDK 17 |
| WSL2, kernel 6.x | Supported | Supported | Same Linux controls when systemd delegation is available | Supported with JDK 17 inside WSL/WSLg; no Windows-JVM bridge |
| Linux ARM64 | Source-compatible, CI evidence pending | Source-compatible | Evidence pending | Source-compatible |
| Native Windows | Not implemented | Not implemented | Not implemented | UI can run, native sensor absent |
| macOS | Not implemented | Not implemented | Not implemented | UI can run, native sensor absent |

Linux tests exercise credential-name discovery, open files, TCP/UDP attribution,
privacy redaction, policy decisions, supervised execution, authenticated audit,
and cgroup descendant cleanup. The cgroup release gate must not be treated as
passing when delegation is unavailable; use `make cgroup-test-required`.

Native Windows support requires a dedicated process and token sensor, ETW-based
activity attribution, Job Object containment, ACL-safe audit storage, and signed
installer validation. Native macOS support similarly requires a dedicated
process sensor, Endpoint Security integration where entitled, sandbox/profile
containment, Keychain-aware storage, and notarized packaging. Linux `/proc`
semantics will not be emulated or advertised as equivalent on those systems.

The Java dashboard is deliberately separated from the native sensor by a
versioned event stream. Future platform adapters can preserve the UI and policy
model while implementing and validating native security semantics independently.
