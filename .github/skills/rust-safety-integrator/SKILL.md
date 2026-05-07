---
name: rust-safety-integrator
description: >
  Use this when integrating safety-critical automotive Rust software: hardware-software
  integration, CI/CD pipeline configuration, cross-compilation, target deployment, software
  release qualification, artifact traceability, and continuous verification. Covers Ferrocene
  toolchain integration, embedded target testing, AUTOSAR deployment, and safety-gated CI.
  Keywords: integrator, integration, CI/CD, cross-compilation, embedded deployment, AUTOSAR,
  hardware-software integration, release qualification, artifact traceability, safety gate,
  cargo build, toolchain, target testing, QEMU, HIL, SIL, safety-critical, automotive
---

# Integrator — Safety-Critical Automotive Rust

## Role Purpose

The integrator assembles independently developed software elements into a **working, qualified system**.
Integration is not "merge and hope" — it is a **structured verification activity** with defined
entry and exit criteria. Every integration step must be traceable and reproducible.

---

## Core Responsibilities

1. Define and execute the **integration build** from Cargo workspace manifest.
2. Configure and maintain the **CI/CD safety gate** with all mandatory checks.
3. Perform **hardware-software integration** testing on target hardware or HIL.
4. Cross-compile for automotive targets (`thumbv7em-none-eabihf`, `aarch64-unknown-linux-gnu`, etc.).
5. Ensure all Ferrocene toolchain qualification requirements are met in the build environment.
6. Maintain **artifact traceability**: every released binary is traceable to a source revision and tool version.
7. Configure AUTOSAR Adaptive execution management and deployment manifests.
8. Run integration test suite at SIL (Software in the Loop) and HIL (Hardware in the Loop) levels.
9. Produce a **Software Integration Report** as a safety case artefact.
10. Manage the release qualification process: configuration freeze, evidence package, sign-off.

---

## Workspace and Build Structure

### Cargo Workspace Layout
```toml
# Cargo.toml (workspace root)
[workspace]
members = [
    "components/brake_controller",     # ASIL-D
    "components/sensor_fusion",        # ASIL-B
    "components/diagnostics",          # QM
    "components/hal_abstraction",      # ASIL-D
    "integration_tests",
]
resolver = "2"

[workspace.dependencies]
# Centrally pinned versions for all safety-relevant dependencies
heapless = { version = "=0.8.0" }
rtic = { version = "=2.1.1", features = ["thumbv7-backend"] }

[profile.release]
panic = "abort"
opt-level = "z"
lto = true
codegen-units = 1    # Required for deterministic builds
```

### Toolchain Pinning
```toml
# rust-toolchain.toml
[toolchain]
channel = "ferrocene-2024.11.0"   # Ferrocene qualified channel
components = ["rustfmt", "clippy", "rust-src"]
targets = ["thumbv7em-none-eabihf", "aarch64-unknown-linux-gnu"]
```
- Toolchain version **must** be pinned, not `stable` or `nightly`.
- Every toolchain upgrade requires a qualification impact analysis.

---

## CI/CD Safety Gate

The CI pipeline is a **safety barrier**. All gates must pass before merge into a protected branch.

### Pipeline Stages

```yaml
# .ci/pipeline.yml (pseudocode — adapt to your CI system)
stages:
  - format_check        # cargo fmt --check
  - lint                # cargo clippy -D warnings (all ASIL lint set)
  - unit_test_host      # cargo test (host target)
  - unit_test_miri      # cargo +nightly miri test
  - unit_test_careful   # cargo +nightly careful test
  - coverage            # cargo tarpaulin --fail-under <ASIL_THRESHOLD>
  - cross_build         # cargo build --target thumbv7em-none-eabihf --release
  - sil_test            # cargo test --target thumbv7em-none-eabihf (QEMU)
  - formal_verify       # cargo kani (on designated proof harnesses)
  - dependency_audit    # cargo audit --deny warnings
  - license_check       # cargo deny check licenses
  - artifact_sign       # Sign and hash release artifacts
```

### Coverage Thresholds by ASIL Level
```toml
# tarpaulin.toml
[report]
fail-under = 80   # ASIL-B minimum; override per-crate

# Per-crate override in Cargo.toml metadata:
[package.metadata.tarpaulin]
fail-under = 100   # ASIL-D: target MC/DC, tarpaulin used for line/branch
```

### Mandatory Deny Policy
```toml
# .cargo/deny.toml
[advisories]
ignore = []    # No ignored advisories without documented justification

[licenses]
allow = ["MIT", "Apache-2.0", "BSD-2-Clause", "BSD-3-Clause"]
# GPL and LGPL require explicit legal review for automotive use

[bans]
deny = [
    { name = "openssl" },        # Prefer rustls for Rust-native TLS
]
```

---

## Cross-Compilation and Target Deployment

### Build for Embedded Target
```bash
# Build ASIL-D crate for ARM Cortex-M4F
cargo build \
  --target thumbv7em-none-eabihf \
  --release \
  -p brake_controller \
  --features asil_d

# Verify binary size against flash budget
size target/thumbv7em-none-eabihf/release/brake_controller
```

### QEMU-Based SIL Testing
```bash
# Run embedded tests under QEMU (Software in the Loop)
cargo test \
  --target thumbv7em-none-eabihf \
  -p brake_controller \
  -- --test-threads=1

# QEMU runner configured in .cargo/config.toml:
# [target.thumbv7em-none-eabihf]
# runner = "qemu-system-arm -cpu cortex-m4 -machine lm3s6965evb -semihosting-config enable=on,target=native -kernel"
```

### HIL Testing
- HIL (Hardware in the Loop) tests run on the actual ECU or representative hardware.
- HIL test results are **mandatory safety artefacts** for ASIL-C/D integration.
- Document test setup, hardware revision, and environmental conditions in the integration report.

---

## AUTOSAR Adaptive Deployment

### Manifest Checklist
- [ ] `exec_config.json` — resource limits (CPU, memory) specified per process
- [ ] `service_instance_manifest.json` — ara::com bindings match software design
- [ ] `machine_design.json` — ASIL partitioning matches architecture (MPU configuration)
- [ ] Watchdog registration in Execution Management for all supervised processes
- [ ] Log and Trace configuration: DLT context IDs registered, log level set to INFO for release

### AUTOSAR Startup Sequence Verification
```bash
# Verify process dependency ordering
# All ASIL-D processes must start before QM processes in the same functional group
ara-exec-verify --manifest exec_config.json --check-ordering
```

---

## Artifact Traceability

Every released binary must be reproducible and traceable:

```
Release Package
├── MANIFEST.txt
│   ├── Git commit hash (SHA-256)
│   ├── Ferrocene toolchain version
│   ├── Cargo.lock (frozen dependency graph)
│   ├── Build date/time (UTC)
│   ├── Build host OS and kernel version
│   └── Target triple
├── brake_controller.elf (stripped release binary)
├── brake_controller.map (linker map, for memory analysis)
├── brake_controller.elf.sha256 (integrity check)
├── test_report.html (unit + integration test results)
├── coverage_report.html (tarpaulin output)
└── kani_proof_report.json (formal verification results)
```

### Reproducible Builds
```toml
# Cargo.toml — enable reproducible builds
[profile.release]
codegen-units = 1
```
Set `SOURCE_DATE_EPOCH` in CI to ensure timestamps are deterministic:
```bash
export SOURCE_DATE_EPOCH=$(git log -1 --format=%ct)
```

---

## Software Integration Report

The integration report is a **safety case artefact** produced at each integration milestone:

```
Integration Report
Version: <semver>
Date: <ISO date>
Integrator: <name>
Configuration: <Git hash + toolchain version>

Integration Steps:
  1. Unit integration (within crate): PASS/FAIL
  2. Component integration (cross-crate): PASS/FAIL
  3. SIL test suite: PASS/FAIL — <N> tests, <N> passed
  4. HIL test suite: PASS/FAIL — <N> tests, <N> passed

CI Gate Results:
  - Format check: PASS
  - Lint (Clippy): PASS
  - Miri: PASS
  - Careful: PASS
  - Coverage: PASS (<N>%)
  - Kani proofs: PASS (<N> proofs)
  - Cargo audit: PASS

Open Issues: <list with severity>
Decision: INTEGRATION COMPLETE / HOLD — requires <action>
```

---

## Common Integration Pitfalls

- **Version skew**: different components built with different `Cargo.lock` states — always lock the workspace.
- **Missing `codegen-units = 1`**: non-deterministic codegen produces binaries that are not reproducible.
- **HIL skipped for schedule reasons**: ASIL-C/D integration sign-off requires HIL evidence; SIL alone is insufficient.
- **AUTOSAR manifest not version-controlled**: manifest divergence between development and release is a safety defect.
- **Ignoring `cargo audit` warnings**: a known-vulnerable dependency in a safety system is a systematic failure.
- **Linker script not reviewed**: a changed linker script can silently misplace ASIL-D code in unprotected memory.

---

## Key References

- ISO 26262-6:2018 #8 — Software Integration and Verification
- ISO 26262-6:2018 #9 — Testing of the Embedded Software
- Ferrocene User Manual — Tool Qualification Workflow
- AUTOSAR Adaptive R21-11 — Execution Management Specification
- cargo-deny — https://embarkstudios.github.io/cargo-deny
- cargo-audit — https://github.com/rustsec/rustsec/tree/main/cargo-audit
- Embedded Rust Book — https://docs.rust-embedded.org/book
- QEMU ARM — https://www.qemu.org/docs/master/system/target-arm.html
