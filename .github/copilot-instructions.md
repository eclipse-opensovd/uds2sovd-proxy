<!--
SPDX-License-Identifier: Apache-2.0
SPDX-FileCopyrightText: 2026 The Contributors to Eclipse OpenSOVD (see CONTRIBUTORS)

See the NOTICE file(s) distributed with this work for additional
information regarding copyright ownership.

This program and the accompanying materials are made available under the
terms of the Apache License Version 2.0 which is available at
https://www.apache.org/licenses/LICENSE-2.0
-->

# GitHub Copilot Instructions — uds2sovd-proxy

This is **Eclipse OpenSOVD uds2sovd-proxy**, an open-source Rust workspace that bridges
UDS (ISO 14229) diagnostic traffic to the SOVD (ISO 22900-4) service-oriented vehicle
diagnostics protocol. It is an Eclipse Foundation project governed by the
[Eclipse Contributor Agreement](https://www.eclipse.org/legal/eca/) and the
Apache-2.0 license.

Use these instructions to guide every code change, review suggestion, and PR
preparation in this repository.

---

## 1. Project Context

| Attribute        | Value                                             |
|------------------|---------------------------------------------------|
| Language         | Rust, edition **2024**                            |
| Async runtime    | `tokio`                                           |
| Logging          | `tracing` crate                                   |
| Error handling   | `thiserror` (library errors), `anyhow` (binaries) |
| Workspace crates | `uds`, `doip`, `sovd`, `uds2sovd` |
| Stable toolchain | **1.88.0** (pinned in `rust-toolchain.toml`; enforced in CI) |
| Nightly rustfmt  | Required for formatting (see #4); `rustup toolchain install nightly-2025-07-14 --component rustfmt` |
| License          | Apache-2.0 only                                   |

---

## 2. Pre-PR Checklist

Before suggesting a PR is ready for review, verify **every item** below passes locally.
CI will gate on all of them.

### 2.1 Build
```sh
cargo build --locked --all-targets
```
- Must pass with zero errors and zero warnings on stable toolchain **1.88.0**.
- Use `--locked` to prevent silent `Cargo.lock` drift.

### 2.2 Tests
```sh
cargo test --locked -- --show-output
```
- All tests must pass on **both Linux and Windows** (the CI matrix covers both).
- Do not use `#[ignore]` to silence a failing test before a PR — fix it or file an issue.

### 2.3 Clippy (pedantic, all warnings as errors)
```sh
cargo clippy --all-targets --all-features -- -D warnings -W clippy::pedantic
```
- Zero warnings allowed — the build is configured with `-D warnings`.
- When you must silence a lint, use `#[allow(...)]` on the smallest scope possible and
  always add a comment explaining why (e.g., `#[allow(clippy::ref_option)] // Not compatible with serde derive`).
- Do **not** add global `#![allow(...)]` without prior review.

### 2.4 Formatting (nightly rustfmt)
```sh
cargo +nightly fmt -- --check \
  --config error_on_unformatted=true,error_on_line_overflow=true,\
format_strings=true,group_imports=StdExternalCrate,imports_granularity=Crate
```
To auto-fix:
```sh
cargo +nightly fmt -- \
  --config error_on_unformatted=true,error_on_line_overflow=true,\
format_strings=true,group_imports=StdExternalCrate,imports_granularity=Crate
```
- Max line width: **100 characters**.
- Import order: `std` → external crates → internal modules (blank line between each group).
- Import granularity: `Crate` (group all imports from the same crate).
- The nightly toolchain is NOT in `rust-toolchain.toml` (stable-only pin). Install once:
  ```sh
  rustup toolchain install nightly-2025-07-14 --component rustfmt
  ```
  The pinned nightly date matches `pr-checks.yml`. Update both together.

### 2.5 Dependency / License Audit
```sh
cargo deny check licenses
cargo deny check advisories
cargo deny check sources
cargo deny check bans
```
- Only these licenses are allowed: `Apache-2.0`, `MIT`, `BSD-3-Clause`, `Zlib`, `ISC`,
  `Unicode-3.0`, `CDLA-Permissive-2.0`.
- All new dependencies must pass `cargo-deny` without adding new `[advisories] ignore`
  entries unless a tracked issue is referenced.

### 2.6 pre-commit hooks
```sh
pre-commit run --all-files
```
Install hooks once per clone: `pre-commit install`. A `.pre-commit-config.yaml` is
committed at the workspace root. It covers:
- Unresolved merge-conflict markers (critical — a stale `<<<<<<<` can silently drop code)
- Trailing whitespace and missing end-of-file newlines
- YAML and TOML syntax validation
- Case-insensitive file name collision checks (Windows CI parity)
- Binary file size guard (max 2 MiB per file)

Note: SPDX header enforcement via `reuse lint` requires a `LICENSES/` directory.
Until that is added, SPDX compliance is enforced by code review and CI annotation.
Track: add `reuse` hook once `LICENSES/Apache-2.0.txt` is committed.

---

## 3. Rust Code Standards

### 3.1 Error Handling

- **Libraries** (`uds`, `doip`, `sovd`): define typed
  errors with `thiserror`. Every error variant must carry enough context for the caller to
  make a recovery decision.
- **Binaries / top-level** (`uds2sovd`): use `anyhow` for ergonomic error propagation.
- **Never use `.unwrap()` or `.expect()` in non-test production paths.** Use `?` or
  explicit match instead.
  ```rust
  // BAD
  let cfg = config.get("key").unwrap();

  // GOOD
  let cfg = config.get("key").ok_or(ConfigError::MissingKey("key"))?;
  ```
- `unwrap()` is acceptable only in `#[cfg(test)]` code; `clippy.toml` already allows it
  in tests.
- Error messages must start with a **capital letter** and must not end with a period.

### 3.2 Async Code

- Use `tokio` primitives only — do not introduce a second async runtime.
- Never block the async executor: no `std::thread::sleep`, no blocking I/O without
  `tokio::task::spawn_blocking`.
- Prefer `tokio::sync::{Mutex, RwLock}` over `std::sync` in async contexts;
  use `parking_lot` primitives for synchronous critical sections.
- Annotate long-running async functions with `#[tracing::instrument]`.

### 3.3 Shared State

- Use `Arc<RwLock<T>>` for read-heavy, write-rare shared state.
- Use `Arc<Mutex<T>>` for write-frequent shared state.
- Document lock ordering when more than one lock is held simultaneously to prevent
  deadlocks.

### 3.4 Constants and Statics

- Use `const` for compile-time values, `static` for global singleton state.
- Do not use magic literals in protocol logic — name every constant.

### 3.5 Unsafe Code

- `unsafe` is not forbidden, but every `unsafe` block **must** have a `// SAFETY:`
  comment explaining which invariants make the operation sound:
  ```rust
  // SAFETY: `ptr` is exclusively owned by this task as guaranteed by
  // the RTIC resource declaration; it is non-null and correctly aligned.
  unsafe { *ptr = value; }
  ```
- Prefer safe abstractions over raw `unsafe`. If you write a safe abstraction over
  an unsafe operation, mark the wrapper function `unsafe` only if callers must uphold
  invariants, or document invariants in `/// # Safety` if the function is safe externally.

### 3.6 Panics

- Panics are forbidden in protocol handling paths. A panic crashes the proxy and
  breaks connected diagnostic tools.
- Proactively review code for hidden panic sites: indexing (`slice[n]`), integer
  arithmetic overflow in debug builds, format string panics.

---

## 4. Code Style

Follow [CODESTYLE.md](../CODESTYLE.md) for the authoritative reference. Key points:

- **Explicit over implicit**: annotate types when they are not obvious from context.
- **Imports**: grouped and ordered (std → external → internal), one blank line between
  groups, granularity at `crate` level.
- **Clippy pedantic**: apply all pedantic lints; deviate only with justification.
- **Tracing**: use `tracing::info!`, `tracing::warn!`, `tracing::error!` for operational
  events. Use `tracing::debug!` for protocol-level details. Avoid `println!`/`eprintln!`
  in library crates.
- **Function length**: keep functions under ~130 lines (`clippy.toml` enforces
  `too-many-lines-threshold = 130`).

---

## 5. Documentation

- **Every public item** (function, struct, enum, trait, module) must have a `///` doc
  comment.
- Document:
  - What the item does (one-line summary).
  - Preconditions / invariants the caller must uphold.
  - Errors returned (link to variants).
  - Panics (if any remain after #3.6 review — they must be unavoidable).
  - `# Examples` block for non-trivial public APIs.
- Private items benefit from doc comments too — add them where the logic is non-obvious.
- Keep comments up to date with code. Stale comments are worse than none.

---

## 6. Testing

- Every new public function or behavior change must be accompanied by unit tests.
- Tests live in a `#[cfg(test)] mod tests { ... }` block in the same file, or in
  `tests/` for integration tests.
- Use descriptive test names that explain the scenario, not the mechanism:
  ```rust
  // BAD
  #[test]
  fn test_parse() { ... }

  // GOOD
  #[test]
  fn parse_routing_activation_with_invalid_length_returns_error() { ... }
  ```
- Test both the happy path and error/edge cases.
- Do not use `#[should_panic]` — match the error value explicitly.
- Mock or stub external dependencies; tests must not require network access or
  real hardware.

---

## 7. Dependencies

- Prefer workspace-level dependency declarations in the root `Cargo.toml`
  `[workspace.dependencies]` table. Avoid duplicating version constraints across crates.
- Always pin with `default-features = false` and enable only features your crate
  actually uses — keeps the build graph minimal and auditable.
- Do not add dependencies that duplicate functionality already available from an
  existing workspace dependency.
- Before adding a new dependency, check:
  1. Is it maintained and has recent releases?
  2. Does it have known security advisories (check `cargo deny check advisories`)?
  3. Is its license in the allowlist in `deny.toml`?
  4. Does it have reasonable compile-time cost?

### 7.1 Known Supply-Chain Constraints (out-of-repo risks)

The following risks are **outside this repository's direct control** and are
documented here so they are not lost when the dependency graph is updated.
They must be re-evaluated whenever `cda-*` dependency revisions are changed.

| Category | Crate / Advisory | Reason | Required Action |
|----------|-----------------|--------|----------------|
| ⚠️ Personal fork | `flatbuffers` (patched via `[patch.crates-io]`) | `cda-database` uses API symbols (`TaggedUnion`, `BuildVector`, `UnionVectorWIPOffsets`) absent from upstream registry releases. Fork owner: `alexmohr`. | Fix must land in `eclipse-opensovd/classic-diagnostic-adapter`. Do **not** update the `flatbuffers` workspace dependency until CDA is fixed. |
| ⚠️ Personal fork | `aide` (patched inside CDA workspace) | CDA patches `aide` for a `serde_qs` API incompatibility. Not directly used by this proxy. Fork owner: `alexmohr`. | Same as above — blocked on CDA. Monitor for fork abandonment. |
| ⚠️ Security advisory | `rsa` crate — RUSTSEC-2023-0071 | Marvin side-channel attack on RSA PKCS#1 v1.5 decryption. Indirect dependency via `jsonwebtoken` → `cda-interfaces`. Proxy code does **not** call RSA operations directly. Suppressed in `deny.toml` with rationale comment. | Remove suppression once CDA updates `jsonwebtoken`. **Never** use the `rsa` crate directly in proxy code. |
| ⚠️ Eclipse governance gap | All `cda-*` crates | The CDA project is a separate Eclipse repo at a pinned git revision. Changes to CDA are not reviewed in this repo's PR process. | Pin CDA to a reviewed revision. When updating the revision, run the full CI matrix and review all new compiler warnings before merging. |

---

## 8. Commit and PR Hygiene

### Commit messages
Follow the **Conventional Commits** format:
```
<type>(<scope>): <subject>

[optional body]

[optional footer: Signed-off-by, Fixes #issue]
```
- Types: `feat`, `fix`, `refactor`, `test`, `docs`, `chore`, `ci`, `perf`.
- Subject: imperative mood, starts with a lowercase letter, no trailing period, max 72 chars.
- Body: explain *why*, not *what* (the diff shows what).
- Sign off every commit: `git commit -s` (required by Eclipse DCO).

### PR description
- Fill the PR template completely.
- Reference the issue being addressed (`Fixes #N` or `Closes #N`).
- List manual verification steps if automated tests do not fully cover the change.
- Mark as **Draft** while work is in progress; move to Ready only when all CI checks pass
  and the checklist in #2 is complete.

### Branch naming
```
<type>/<short-description>
# Examples:
feat/sovd-session-timeout
fix/doip-routing-activation-length
chore/bump-tokio-1-50
```

---

## 9. Licensing and Copyright

- Every source file must carry an SPDX header:
  ```
  // SPDX-License-Identifier: Apache-2.0
  // SPDX-FileCopyrightText: 2026 The Contributors to Eclipse OpenSOVD (see CONTRIBUTORS)
  ```
  Use `//` for Rust files, `#` for TOML/YAML/shell, `<!--` / `-->` for Markdown/XML.
- Do not copy-paste code from other projects without verifying its license is compatible
  with Apache-2.0 and adding proper attribution.
- The `pre-commit` hooks verify SPDX headers — run them before committing.

---

## 10. Security

- Treat all data received over the network (DoIP, SOVD REST) as untrusted input.
  Validate lengths and field values **before** using them.
- Do not log sensitive data (ECU security keys, auth tokens, PII).
- Integer arithmetic on protocol-supplied lengths must use checked or saturating
  arithmetic (`checked_add`, `saturating_sub`) to prevent wrapping panics or overflows.
- Do not use `std::process::exit` or similar hard shutdown paths in library code —
  let the caller decide how to handle unrecoverable states.

---

## 11. Performance

- Profile before optimising. Introduce complexity only when benchmarks demonstrate need.
- Prefer allocation-light paths in hot protocol decode/encode loops (`bytes::Bytes`,
  zero-copy slicing over owned `Vec<u8>` where possible).
- Avoid `clone()` on large data in hot paths; prefer `Arc` sharing or references.

---

## 12. AI-Assisted Workflow Tips

When using Copilot to generate or review code in this repository:

1. **Verify CI parity**: always run the #2 checklist locally — Copilot suggestions may
   pass syntax checks but still fail pedantic clippy or nightly fmt.
2. **Check license**: if Copilot suggests code derived from another project, confirm
   the source is Apache-2.0 or MIT compatible before accepting.
3. **Unsafe scrutiny**: if Copilot generates an `unsafe` block, always add the
   `// SAFETY:` justification yourself — do not accept generated safety comments
   without verifying them.
4. **Test coverage**: Copilot-generated functions should always be followed by a
   prompt to generate corresponding test cases. Review those tests critically.
5. **Dependency suggestions**: if Copilot suggests adding a new crate, run the
   #7 checklist before committing it to `Cargo.toml`.
6. **Tracing over println**: replace any Copilot-generated `println!`/`dbg!` in
   library code with the appropriate `tracing` macro.

---

## 13. Available AI Skills

This repository ships a set of **domain-specific skills** under `.github/skills/`.
Each skill gives Copilot deep, role-specific knowledge tailored to safety-critical
automotive Rust. Copilot loads the relevant skill automatically when your question
matches its keywords, but you can also invoke one explicitly by mentioning its name.

> **How to invoke**: In any Copilot Chat prompt, include the skill name — e.g.
> *"As the rust-safety-implementer, review this DoIP handler for panic paths."*

### Skill Reference

| Skill | Invoke when you need to… |
|---|---|
| **rust-safety-designer** | Design a new crate, derive safety goals, model fault propagation across `uds` / `doip` / `sovd`, perform HARA/FMEA, or decide ASIL decomposition for a feature. |
| **rust-safety-implementer** | Write or refactor Rust code in a safety path — bounded loops, `no_std` discipline, `panic = "abort"` placement, `cargo-careful`/`miri` discipline, or MISRA-Rust-equivalent patterns. |
| **rust-safety-integrator** | Configure CI pipelines, cross-compile for embedded targets, set up safety-gated workflows, qualify toolchain artefacts, or trace integration evidence for a release. |
| **rust-safety-interface-developer** | Design or review public APIs in `uds`, `doip`, or `sovd` — newtype patterns, phantom-type state machines, trait contracts, compile-time safety guarantees. |
| **rust-safety-reviewer** | Conduct a structured code review with ASIL-level objectives — unsafe block audit, test completeness check, doc completeness, or requirement traceability verification. |
| **rust-safety-rust-expert** | Dig into deep Rust: memory ordering, async runtime internals, FFI safety, linker layout, lifetime variance, macro hygiene, or `unsafe` abstraction soundness. |
| **rust-safety-safety-review** | Perform a safety case assessment, verify ASIL compliance evidence, audit DFA/DIA, review safety manual completeness, or prepare a functional-safety sign-off artefact. |
| **rust-safety-software-critique** | Adversarially analyse code — run Kani proofs, guide `cargo-fuzz`/AFL campaigns, interpret static analysis findings, perform structured fault injection, or bound WCET. |
| **rust-safety-usability-review** | Evaluate API ergonomics — does the API make misuse a compile error? Are error messages actionable? Is the "pit of success" the default path? |

### Skill–Workflow Mapping for This Project

The table below maps common development activities in uds2sovd-proxy to the skill(s) that
provide the most relevant guidance.

| Activity | Primary skill | Supporting skill |
|---|---|---|
| Adding a new DoIP payload type in `doip` | `rust-safety-implementer` | `rust-safety-interface-developer` |
| Designing the SOVD session lifecycle | `rust-safety-designer` | `rust-safety-interface-developer` |
| Reviewing a PR that touches `sovd` | `rust-safety-reviewer` | `rust-safety-usability-review` |
| Hardening protocol length parsing against malformed input | `rust-safety-software-critique` | `rust-safety-implementer` |
| Extending CI with a new safety gate | `rust-safety-integrator` | — |
| Auditing a new `unsafe` block in `doip` | `rust-safety-rust-expert` | `rust-safety-reviewer` |
| Adding a new public API to `uds` | `rust-safety-interface-developer` | `rust-safety-usability-review` |
| Preparing a release and its safety evidence | `rust-safety-safety-review` | `rust-safety-integrator` |

---

## Quick Reference — Commands

| Task                        | Command                                                                                        |
|-----------------------------|-----------------------------------------------------------------------------------------------|
| Build                       | `cargo build --locked`                                                                        |
| Test                        | `cargo test --locked`                                                                         |
| Clippy (pedantic)           | `cargo clippy --all-targets --all-features -- -D warnings -W clippy::pedantic`               |
| Format check (nightly)      | `cargo +nightly fmt -- --check --config error_on_unformatted=true,error_on_line_overflow=true,format_strings=true,group_imports=StdExternalCrate,imports_granularity=Crate` |
| Format fix (nightly)        | `cargo +nightly fmt -- --config error_on_unformatted=true,error_on_line_overflow=true,format_strings=true,group_imports=StdExternalCrate,imports_granularity=Crate`        |
| Deny check                  | `cargo deny check`                                                                            |
| Pre-commit (all files)      | `pre-commit run --all-files`                                                                  |

## Quick Reference — Skills

| Task                                         | Skill to invoke                      |
|----------------------------------------------|--------------------------------------|
| Write / refactor production Rust code        | `rust-safety-implementer`            |
| Design a new feature or crate boundary       | `rust-safety-designer`               |
| Review a PR                                  | `rust-safety-reviewer`               |
| Design or audit a public API / trait         | `rust-safety-interface-developer`    |
| Deep Rust language / `unsafe` questions      | `rust-safety-rust-expert`            |
| CI/CD, cross-compilation, release artefacts  | `rust-safety-integrator`             |
| Fuzzing, formal proofs, fault injection      | `rust-safety-software-critique`      |
| API ergonomics / developer experience        | `rust-safety-usability-review`       |
| Safety case, ASIL evidence, sign-off         | `rust-safety-safety-review`          |

---

*These instructions complement — and do not replace — [CONTRIBUTING.md](../CONTRIBUTING.md)
and [CODESTYLE.md](../CODESTYLE.md). When in doubt, consult those documents or ask on the
[opensovd-dev mailing list](https://accounts.eclipse.org/mailing-list/opensovd-dev).*
