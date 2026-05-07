<!--
SPDX-License-Identifier: Apache-2.0
SPDX-FileCopyrightText: 2026 The Contributors to Eclipse OpenSOVD (see CONTRIBUTORS)

See the NOTICE file(s) distributed with this work for additional
information regarding copyright ownership.

This program and the accompanying materials are made available under the
terms of the Apache License Version 2.0 which is available at
https://www.apache.org/licenses/LICENSE-2.0
-->

# Open Work Items — uds2sovd-proxy

Findings captured during the initial infrastructure review (2026-05-05).
Items are grouped by category and ordered within each group by priority.

> **Context:** this is a safety-critical automotive platform library targeting
> ISO 14229 (UDS) / ISO 22900-4 (SOVD) / ISO 26262 compliance. Every item
> below should be evaluated against that context before being closed.

---

## Legend

| Symbol | Meaning |
|--------|---------|
| 🔴 | Blocks CI / build / safety evidence |
| 🟡 | Should be resolved before a production release |
| 🔵 | Good-to-have / tech-debt |
| ⛔ | Out of this repo's direct control — requires upstream action |

---

## 1. Toolchain & Local Developer Setup

- [ ] 🔴 **Install pinned stable toolchain 1.88.0 on all developer machines.**
  `rust-toolchain.toml` now pins it, so `rustup` will install it automatically
  on the next `cargo` invocation. Until then, local builds use whatever
  default is active (1.95.0 at time of writing, which is fine but not
  the CI-qualified version).
  ```sh
  rustup toolchain install 1.88.0 --component clippy rustfmt
  ```

- [ ] 🔴 **Install nightly rustfmt toolchain for format checks.**
  The pinned nightly date must match `pr-checks.yml`.
  ```sh
  rustup toolchain install nightly-2025-07-14 --component rustfmt
  ```

- [ ] 🔴 **Install `cargo-deny` locally (same version as CI: 0.18.9).**
  Without it, the dependency/license audit step cannot be run locally before
  a PR is opened, violating the pre-PR checklist in CONTRIBUTING.md.
  ```sh
  cargo install --locked --version 0.18.9 cargo-deny
  ```

- [ ] 🔴 **Install `pre-commit` and activate hooks.**
  `.pre-commit-config.yaml` was created but hooks are not yet activated on
  any developer machine or enforced in the existing CI matrix.
  ```sh
  pip install pre-commit   # or: pipx install pre-commit
  pre-commit install
  ```

---

## 2. CI / Workflow

- [ ] 🟡 **`build.yml`: `cargo deny` only runs on Linux.**
  All four deny checks (`licenses`, `advisories`, `sources`, `bans`) are
  gated on `runner.os == 'Linux'`. This is intentional for performance (the
  dependency graph is platform-independent) but is undocumented in the
  workflow file. Add a comment so future contributors do not remove the gate
  under the assumption it is a bug.

- [ ] 🟡 **`pr-checks.yml`: nightly format check is advisory, not enforced.**
  The nightly-pinned step uses `fail-on-format-error: "false"`. This means
  format regressions against the nightly formatter only appear as review
  comments, never as a blocking CI failure. Consider promoting to
  `fail-on-format-error: "true"` once the codebase is fully formatted under
  the nightly config.

- [ ] 🟡 **`pr-checks.yml`: nightly-latest step is `continue-on-error: true`.**
  This is correct for forward-compatibility, but there is no alert or
  dashboard tracking breakage against upcoming nightly releases. Consider
  adding a Slack/mailing-list notification when this step fails so nightly
  regressions are caught before they become stable regressions.

- [ ] 🔵 **No integration or end-to-end test job in CI.**
  The current CI only runs unit tests (`cargo test`). For a protocol
  translation proxy there should be an integration test that exercises a full
  DoIP → UDS → SOVD round-trip (even against the mock gateway). This is
  especially important for safety evidence.

- [ ] 🔵 **No `cargo doc` or documentation build step in CI.**
  Missing or broken `///` doc comments are not caught today. Add
  `cargo doc --no-deps --document-private-items` with `-D rustdoc::broken_intra_doc_links`.

---

## 3. Code Quality — Clippy (deferred from infra session, code not yet touched)

The following `clippy -D warnings -W clippy::pedantic` errors exist in the
current codebase and **block CI on the qualified 1.88.0 toolchain**.
These must be fixed before opening a PR against upstream.

- [ ] 🔴 **`proxy-core`: unused import `Encoder`**
  Location TBD (service_resolver module area). Remove or use the import.

- [ ] 🔴 **`proxy-core`: hand-coded well-known IP address**
  `clippy::manual_ip_addr` — replace literal with `Ipv4Addr::UNSPECIFIED` or
  equivalent constant.

- [ ] 🔴 **`proxy-core`: item in documentation missing backticks** (multiple)
  `clippy::doc_markdown` — wrap type/function names in backticks in doc
  comments.

- [ ] 🔴 **`proxy-core`: `map(<f>).unwrap_or(false)` on `Option`**
  `clippy::option_map_unwrap_or` or `clippy::map_unwrap_or` — replace with
  `Option::is_some_and(f)` or `Option::map_or(false, f)`.

- [ ] 🔴 **`proxy-core` tests: useless use of `vec![]`** (two occurrences)
  Replace `vec![]` with `Vec::new()` or `<Vec<_>>::new()`.

- [x] 🔴 **`doip-server`: unused import `DoipParseable`**
  Remove the import if the trait is not used directly.

- [ ] 🔴 **`doip-server`: item in documentation missing backticks**
  Same as proxy-core finding above.

---

## 4. Dependencies & Supply-Chain (out-of-repo risks)

> These items require action in upstream repositories.
> They are documented here for traceability and must be re-evaluated on every
> `cda-*` revision bump.

- [ ] ⛔ 🟡 **`flatbuffers` personal fork dependency must be upstreamed.**
  `cda-database` uses `TaggedUnion`, `BuildVector`, `UnionVectorWIPOffsets`
  symbols absent from upstream `flatbuffers 25.x`. A `[patch.crates-io]` in
  this workspace's `Cargo.toml` is the only fix. If the fork
  (`alexmohr/flatbuffers@0ba3307d`) is abandoned or the registry crate is
  updated, the build breaks.
  **Action:** open or follow an issue in
  `eclipse-opensovd/classic-diagnostic-adapter` to either:
  (a) upstream the patch to the official `flatbuffers` crate, or
  (b) regenerate the flatbuffers code against the upstream stable API.

- [ ] ⛔ 🟡 **`aide` personal fork dependency must be resolved.**
  `alexmohr/aide` patches a `serde_qs` version incompatibility inside CDA.
  Not used directly by this proxy. Same governance concern as `flatbuffers`.
  **Action:** follow `eclipse-opensovd/classic-diagnostic-adapter`.

- [ ] ⛔ 🟡 **`RUSTSEC-2023-0071` — `rsa` Marvin attack suppression must be lifted.**
  Suppressed in `deny.toml` because the proxy does not call RSA directly.
  Blocked on CDA updating `jsonwebtoken` to a version that no longer depends
  on a vulnerable `rsa` crate.
  **Action:** remove `ignore = ["RUSTSEC-2023-0071"]` from `deny.toml` once
  the CDA dependency graph is clean.

- [ ] ⛔ 🔵 **Pin `cda-*` dependency to a verified Eclipse-reviewed revision.**
  Currently pinned to `cf7fd9c18a7c49467e9e6c9ceae1e771c613e49b`. Changes
  to CDA are not reviewed in this repo's PR process. Every time this revision
  is updated, the full CI matrix must be re-run and all new compiler warnings
  reviewed before merging.

---

## 5. Documentation

- [x] 🔴 **Sample MDD relocated to `examples/mdd/`.**
  `FLXCNG1000.mdd` and its license file moved from `testcontainer/mdd/` to
  `examples/mdd/`. The `--mdd-dir` CLI argument and its hardcoded default have
  been removed; users now supply `--mdd-file /path/to/ECU.mdd` directly.

- [ ] 🟡 **`README.md`: complete the empty `prerequisites` section.**
  Minimum viable content: required Rust version, how to install `rustup`,
  `cargo-deny`, and `pre-commit`; how to obtain / generate a test MDD file.

- [ ] 🟡 **`README.md`: complete the empty `usage` section.**
  Minimum viable content: full run command with all required flags, example
  config snippet, how to switch between mock and real SOVD gateway.

- [ ] 🟡 **`README.md`: complete the architecture section.**
  The PlantUML source and rendered SVG diagrams already exist in
  `docs/service_resolver/`. Embed or link them. Add a crate-map showing how
  `proxy-core`, `proxy-doip`, `proxy-sovd`, `proxy-main`, and `doip-server`
  relate to each other.

- [ ] 🟡 **`CODESTYLE.md`: license allowlist is inconsistent with `deny.toml`.**
  `CODESTYLE.md` lists only `Apache-2.0` and `MIT` as allowed licenses, but
  `deny.toml` also allows `BSD-3-Clause`, `Zlib`, `ISC`, `Unicode-3.0`, and
  `CDLA-Permissive-2.0`. Update `CODESTYLE.md` to match.

- [ ] 🔵 **Add a `NOTICE` file.**
  Eclipse Foundation projects are expected to ship a `NOTICE` file listing
  copyright holders and any attribution requirements of third-party
  dependencies. Required for REUSE compliance and distribution.

- [ ] 🔵 **Add a `SECURITY.md` file.**
  Documents how to report security vulnerabilities privately. GitHub
  displays this file on the repo Security tab and links it from the
  dependency graph advisories panel.

- [ ] 🔵 **Add a `CHANGELOG.md` (or use GitHub Releases).**
  No mechanism exists today to communicate breaking changes, new features,
  or fixed bugs to downstream consumers of the proxy.

---

## 6. Eclipse / REUSE Compliance

- [ ] 🟡 **Add `LICENSES/Apache-2.0.txt` to enable REUSE tooling.**
  All source files already carry SPDX headers. Adding the `LICENSES/`
  directory is the last step to make `reuse lint` pass, after which the
  `reuse` pre-commit hook can be uncommented in `.pre-commit-config.yaml`.

- [ ] 🟡 **Add SPDX license file for `FLXCNG1000.mdd`.**
  The MDD test file has no accompanying `.license` sidecar file.

---

## 7. Crate Structure (deferred architectural decision)

- [ ] 🔵 **Clarify the relationship between `doip-server` and `proxy-doip`.**
  Two DoIP implementations exist in the workspace:
  - `doip-server`: standalone server with its own binary entry point, codec,
    session manager, and stub UDS handlers.
  - `proxy-doip`: the DoIP transport layer wired into `proxy-main`.
  `proxy-main` depends only on `proxy-doip`. `doip-server` is not depended on
  by any other crate. Their intended roles (simulation tool vs. production
  library) should be documented in crate-level `//!` doc comments and the
  README architecture section. If `doip-server` is a test/simulation tool,
  consider moving it to `tools/doip-server` to make the workspace structure
  self-evident.

- [x] 🔵 **A1 decision: keep `doip-server` as-is; migrate superior parts into `proxy-doip`.**
  `doip-server` contains several capabilities that `proxy-doip` lacks:
  - `DoipCodec` (`tokio_util::codec` Decoder/Encoder pair) — replaces the
    hand-rolled byte buffer + manual drain loop in `proxy-doip/handler.rs`.
  - `DoipParseable` / `DoipSerializable` traits — uniform parse/serialise
    contract replacing ad-hoc `from_payload` / `to_bytes` methods.
  - `DoipPayload` typed dispatch enum — replaces the raw `u16` match in
    `proxy-doip`.
  - Typed `routing_activation::ActivationType` / `ResponseCode` enums —
    `proxy-doip` uses a bare `u8` constant.
  - `SessionState` enum (Connected → RoutingActive → Closed) — richer than
    the `bool` flag in `proxy-doip::Session`.
  - ISO-compliant `GenericHeaderNack` responses — missing in `proxy-doip`.
  - `UdsHandler` trait — the key abstraction that breaks the `proxy-doip` →
    `SovdDiagHandler` concrete coupling (see A2 finding below).
  Planned migration: adopt `UdsHandler`, `DoipCodec`, `DoipPayload`, and
  `SessionState` from `doip-server` into `proxy-doip` incrementally.
  `doip-server` will be retired once `proxy-doip` covers all its capabilities.
  Track: <https://github.com/eclipse-opensovd/uds2sovd-proxy/issues/TBD>.

---

## 8. Safety Evidence Gaps (safety-critical context)

- [ ] 🟡 **No hazard analysis (HARA) or safety goal artefacts committed.**
  For ISO 26262 compliance, hazard analysis and safety goals must be
  traceable from requirements through design to code. No such artefacts
  exist in the repository.

- [ ] 🟡 **No requirement traceability.**
  Test cases cannot be traced to requirements. Each test should reference
  the requirement or safety goal it validates.

- [ ] 🔵 **No static analysis beyond clippy (e.g., Kani, cargo-careful, Miri).**
  For a safety-critical library, formal verification or model-checked
  property tests on protocol boundary parsing functions should be considered.
  See `.github/skills/rust-safety-software-critique/SKILL.md` for guidance.

- [ ] 🔵 **No fuzz targets for protocol parsing.**
  `doip-server`'s frame parser and `proxy-core`'s MDD resolver are
  network-facing and should have `cargo-fuzz` targets to detect
  length-handling panics and integer overflows before they reach production.

---

## 9. Design Critique — Architecture, Type System, API, Concurrency

> Findings from the 2026-05-05 design review session.
> Items are ordered by recommended execution sequence.
> Each item carries the cluster prefix (A/B/C/D/E) for cross-reference.

### Approach and Methodology

The review follows these Rust-idiomatic principles:

- **If it compiles, it works** — encode invariants in the type system so
  illegal states are unrepresentable, not just undocumented.
- **Make the pit of success wide** — correct usage should be the easy path;
  misuse should require active effort (or preferably not compile).
- **Fearless concurrency** — replace ad-hoc atomics with structured primitives
  (`Semaphore`, `tokio::sync::Mutex`) that enforce the invariant by construction.
- **Functional core, imperative shell** — pure functions for
  protocol encoding/decoding; side effects only at the edges.
- **Single source of truth** — one definition per concept, re-exported
  everywhere else.

### Ecosystem Context

The `eclipse-opensovd` organisation hosts several repos whose code is directly
relevant to this proxy:

| Repo | Relevant asset | How to reuse |
|------|---------------|-------------|
| [opensovd-core](https://github.com/eclipse-opensovd/opensovd-core) | `opensovd-client` — typed SOVD REST client built on `hyper` + Tower layers, with builder pattern, Unix socket support, and mock connector for tests | Replace hand-rolled `reqwest` client in `proxy-sovd::SovdClient` |
| [opensovd-core](https://github.com/eclipse-opensovd/opensovd-core) | `opensovd-models` — canonical SOVD data model types (`DataList`, `ReadResponse`, `WriteRequest`) | Replace the local `DataResponse` schema type |
| [opensovd-core](https://github.com/eclipse-opensovd/opensovd-core) | `opensovd-mocks` — mock HTTP connector for unit tests | Unblock SOVD-layer unit tests without a live server |
| [classic-diagnostic-adapter](https://github.com/eclipse-opensovd/classic-diagnostic-adapter) | `cda-interfaces` — already a workspace dependency | Already used; track for upstream fixes to `flatbuffers`/`aide` forks |
| [odx-converter](https://github.com/eclipse-opensovd/odx-converter) | ODX → MDD conversion tooling | Enables testing with ODX-format vehicle databases |

---

### A — Architecture / Crate Boundaries

- [ ] 🔴 **A1 — Eliminate `doip-server` after migrating superior parts to `proxy-doip`.**
  See Section 7 above for the decision record and migration plan.
  Priority components to migrate, in order:
  1. `UdsHandler` trait (see A2 below) — unblocks all other work.
  2. `DoipCodec` (tokio-util Decoder/Encoder) — replaces the hand-rolled
     4-state buffer loop in `ConnectionHandler::handle`.
  3. `DoipPayload` enum — typed dispatch replacing the raw `u16` match.
  4. `SessionState` enum — richer than the current `bool` flag.
  5. ISO-correct `GenericHeaderNack` response construction.
  Track in a dedicated issue; keep `doip-server` read-only until then.

- [x] 🔴 **A2 — Introduce `UdsHandler` trait to break DoIP → SOVD coupling.**
  `proxy-doip` currently hardcodes `Arc<SovdDiagHandler>` making it
  impossible to test the transport layer in isolation.

  The `doip-server` crate already defines a synchronous version:
  ```rust
  pub trait UdsHandler: Send + Sync {
      fn handle(&self, request: UdsRequest) -> UdsResponse;
  }
  ```
  For the proxy, an async version is needed because SOVD calls are async:
  ```rust
  // proxy-core (shared contract, no SOVD dependency)
  #[async_trait]
  pub trait DiagHandler: Send + Sync {
      async fn handle_uds(&self, request: UdsRequest) -> UdsResponse;
  }
  ```
  Where `UdsRequest` / `UdsResponse` are the typed wrappers from
  `doip-server` (or equivalents promoted to `proxy-core`).
  `DoIpServer<H: DiagHandler>` replaces `DoIpServer { diag_handler: Arc<SovdDiagHandler> }`.
  `SovdDiagHandler` implements `DiagHandler`. Tests inject `MockDiagHandler`.

- [x] 🟡 **A3 — Encapsulate `ServiceResolver` fields behind named methods.**
  `ServiceResolver.resolver`, `.encoder`, `.metadata` are `pub` fields
  exposing implementation detail. Callers in `proxy-sovd` navigate three
  sub-objects directly. Replace with delegating methods:
  `resolve_did`, `build_uds_response`, `response_metadata`.
  The sub-structs become private implementation detail.

- [x] 🟡 **A4 — Replace monolithic `Arc<Config>` injection with config slices.**
  Five components (`DoIpServer`, `ConnectionHandler`, `SovdDiagHandler`,
  `SovdMapper`, `SovdClient`) all hold `Arc<Config>`.
  Each only uses a small subset. Pass only the relevant sub-config:
  `SovdClient::new(SovdConfig)`, `ConnectionHandler::new(DoipConnectionConfig, …)`.
  This makes each component's real dependencies visible and testable.
  ✅ **Done**: Added `DoipConnectionConfig { ecu_logical_address, source_address }` to
  `proxy-core::config` (exported from `proxy-core::lib`). `ConnectionHandler` now takes
  `DoipConnectionConfig` (Copy, no Arc). `DoIpServer` takes `ServerConfig` +
  `DoipConnectionConfig`. `SovdDiagHandler` takes `ecu_name: String`.
  `SovdMapper::new` takes `ecu_name: String` + `&SovdConfig`. `proxy-main` constructs
  all slices from `Config` and passes them down — `Arc<Config>` is gone from the
  injection graph. All 303 tests pass; zero clippy warnings.

- [ ] 🔵 **A5 — Adopt `opensovd-client` to replace `proxy-sovd::SovdClient`.**
  `opensovd-client` (from `eclipse-opensovd/opensovd-core`) is a production-
  quality typed SOVD REST client using `hyper` and Tower middleware, with:
  - Builder pattern for URL, connector, and middleware layers.
  - First-class Unix domain socket support.
  - Mock HTTP connector (`opensovd-mocks`) for unit tests.
  - `opensovd-models` typed request/response types (`ReadResponse`,
    `WriteRequest`) replacing the local `DataResponse`.
  Migration path: add `opensovd-client` as a workspace dependency; adapt
  `SovdMapper` to use it; delete `SovdClient` and `schema.rs`.
  Prerequisite: verify license compatibility (Apache-2.0 ✔) and pin to a
  reviewed commit.

---

### B — Type System

- [x] 🟡 **B1 — Replace `LoggingConfig` string fields with enums.**
  `level: String` and `format: String` are stringly-typed. Invalid values
  (`"verbose"`, `"xml"`) are only caught at runtime. Use:
  ```rust
  #[derive(Debug, Clone, Deserialize, Default)]
  #[serde(rename_all = "lowercase")]
  pub enum LogFormat { #[default] Pretty, Json }
  ```
  The `format == "json"` string comparison in `main.rs` becomes a safe
  enum match.

- [ ] 🟡 **B2 — Remove untyped JSON from the domain model.**
  `ResolvedService.params: serde_json::Map<String, serde_json::Value>` and
  the `Map<String, Value>` parameter to `process_write_data_request` leak
  raw JSON into domain types. Structural validation is bypassed.
  Introduce a typed `ServiceParams` representation even if it wraps the map
  initially; enforce validation at the boundary where CDA produces it.

- [x] 🟡 **B3 — Replace `Session` bool flag with an enum state machine.**
  ```rust
  // Current — two booleans; impossible states not prevented
  struct Session { routing_activated: bool, source_address: Option<u16> }

  // Idiomatic Rust — impossible state (activated + no address) unrepresentable
  enum Session { Inactive, Active { source_address: u16 } }
  ```
  `doip-server::server::session::SessionState` already defines
  `Connected / RoutingActive / Closed` — adopt that model.

- [ ] 🟡 **B5 — Replace raw `u8` SID fields with a `UdsSid` typed enum.**
  `UdsMessage.service_id` is a raw `u8`. The dispatch `match` on it has a
  catch-all `_ =>` arm, so adding a new SID without handling it is **silent**.
  Replace with:
  ```rust
  // proxy-core (new file: src/uds.rs or extend error.rs)
  #[derive(Debug, Clone, Copy, PartialEq, Eq)]
  #[non_exhaustive]
  pub enum UdsSid {
      SessionControl,             // 0x10
      ReadDataByIdentifier,       // 0x22
      WriteDataByIdentifier,      // 0x2E
      TesterPresent,              // 0x3E
      // … extend as services are added …
  }

  impl UdsSid {
      /// Positive-response SID (ISO 14229-1 #8.3).
      pub const fn positive_response_byte(self) -> u8 { self as u8 | 0x40 }
      /// Minimum UDS request payload bytes for this service (SID excluded).
      pub const fn min_request_bytes(self) -> usize { … }
  }

  impl TryFrom<u8> for UdsSid { type Error = UnknownSid; … }
  impl From<UdsSid> for u8 { … }
  ```
  Changes downstream: `UdsMessage.service_id: UdsSid`; `Nrc::response_for`
  accepts `UdsSid` instead of `u8`; `UNKNOWN_SERVICE_ID` constant goes away;
  per-SID length constants (`MIN_RDBI_DATA_LENGTH`, etc.) move onto the enum;
  dispatch becomes exhaustive (compiler enforces handling of new variants).
  Prerequisite: none, but do after C2.

- [ ] 🟡 **B6 — Newtype wrappers for `u16` protocol fields to prevent parameter swaps.**
  `DiagnosticMessage` has `source_address: u16` and `target_address: u16`.
  `SovdMapper` / `ConnectionHandler` pass these around as bare `u16`; a
  swapped argument compiles silently and produces a live ECU bug.
  Introduce:
  ```rust
  // proxy-core
  #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
  pub struct EcuAddress(pub u16);

  #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
  pub struct DataIdentifier(pub u16);
  ```
  `DiagnosticMessage.source_address: EcuAddress`, `target_address: EcuAddress`.
  `SovdMapper::handle_read_did(did: DataIdentifier, …)` instead of `did: u16`.
  Passing a `DataIdentifier` where an `EcuAddress` is expected becomes a
  **compile error**. Consider adding `impl From<EcuAddress> for u16` for
  zero-cost boundary crossing.

- [x] 🟡 **B4 — Single source of truth for UDS SID constants.**
  `proxy_core::service_resolver::uds_service_ids` duplicates
  `cda_interfaces::service_ids`. Call sites mix both. Canonical definition:
  keep the local `uds_service_ids` module in `proxy-core` as the one
  true source; re-export as needed; stop importing `cda_interfaces::service_ids`
  directly in `proxy-doip` and `proxy-sovd`.

  `doip-server::uds::handler::service_id` is a *third* copy — consolidate
  all three once `doip-server` parts migrate into `proxy-core`.

---

### C — API Design

- [x] 🟡 **C1 — Split `ConnectionHandler` (violates single responsibility).**
  One struct currently handles: TCP read-loop, partial-frame buffering,
  DoIP frame parsing, byte-level re-sync, session state, UDS dispatch,
  DoIP response framing, and byte writes (~350 lines).
  Split into focused components:
  - `FrameCodec` — adopt `doip-server::DoipCodec` (tokio-util Decoder/Encoder).
  - `Session` enum (see B3).
  - `UdsDispatcher` — SID-based dispatch to the `DiagHandler` trait (see A2).
  - `ConnectionHandler` — thin coordinator wiring the three above.
  Prerequisite: A2 (trait) must exist before this split is testable.
  ✅ **Done**: Extracted `UdsDispatcher` to `proxy-doip/src/uds_dispatcher.rs`.
  `UdsMessage` struct and all UDS-semantic constants moved with it.
  `ConnectionHandler` retains only transport concerns (TCP loop, framing, session,
  DoIP protocol dispatch). 8 new `UdsDispatcher` unit tests added; all 42
  `proxy-doip` tests pass.

- [x] 🟡 **C2 — Centralise NRC negative-response construction.**
  At least three different spellings of the NRC pattern appear in
  `proxy-doip`. Add a method on `Nrc`:
  ```rust
  impl Nrc {
      pub fn response_for(self, request_sid: u8) -> [u8; 3] {
          [0x7F, request_sid, self as u8]
      }
  }
  ```

- [x] 🟡 **C3 — Remove config field duplication in `SovdMapper`.**
  `SovdMapper` copies `ecu_name`, `mock_gateway`, `gateway_url`,
  `api_version` from `SovdConfig` that `SovdClient` already holds.
  Hold a single `SovdConfig` reference; derive the values from it.
  ✅ **Done**: Removed `mock_gateway`, `gateway_url`, `api_version` from `SovdMapper`.
  Added `is_mock()`, `read_url()`, `write_url()`, `auth_url()` accessors to `SovdClient`
  (C4 done simultaneously). `SovdMapper::new` now takes only `(ecu_name, SovdClient)`.

- [x] 🔵 **C4 — Replace `format!` URL construction with a typed URL builder.**
  SOVD URL construction is duplicated across `SovdClient` (3 call sites)
  and `SovdMapper`. A `SovdPaths` helper (or methods on `SovdConfig`)
  avoids scattered template strings and catches path-segment errors at
  compile time via typed newtypes.
  ✅ **Done**: URL templates centralised as `read_url()`, `write_url()`, `auth_url()` on
  `SovdClient`. All 4 call sites (3 in `SovdClient`, 1 in `SovdMapper`) replaced.

---

### D — Concurrency / Safety

- [x] 🔴 **D2 — Fix TOCTOU race in connection-limit check.**
  ```rust
  // BUG: N simultaneous arrivals can all pass when active == limit - 1
  let previous = self.active_connections.fetch_add(1, Ordering::AcqRel);
  if previous >= limit { self.active_connections.fetch_sub(1, ...); reject; }
  ```
  Replace with `tokio::sync::Semaphore::try_acquire()`. The semaphore
  permits atomic acquisition and prevents over-admission by construction.

- [ ] 🟡 **D1 — Add OAuth2 token expiry tracking to `SovdClient`.**
  The access token is cached forever. Tokens have an `expires_in` field.
  Long-running proxies will silently receive HTTP 401 with no recovery.
  Store `(token, Instant::now() + Duration::from_secs(expires_in - margin))`;
  re-authenticate when `now() >= expiry`.

---

### E — Testability

- [x] 🔴 **E1 — Add `DiagHandler` mock to unblock unit testing of DoIP layer.**
  No test today exercises `ConnectionHandler` or `DoIpServer`.
  Once the `DiagHandler` trait (A2) exists, a `MockDiagHandler` can be
  injected to test routing activation, frame parsing, and UDS dispatch
  without any SOVD dependency.

- [ ] 🟡 **E2 — Extract `generate_mock_response_data` from `SovdClient`.**
  Mock/test infrastructure has leaked into the production HTTP client.
  Move this to a `MockSovdGateway` type (implementing a `SovdGateway` trait)
  that lives in test code or a separate `proxy-sovd-test-utils` crate.

- [ ] 🟡 **E3 — Add end-to-end integration test for the full round-trip.**
  Wire a real `DoipMessage` → `ConnectionHandler` → `MockDiagHandler` →
  response bytes test. This is the minimum safety evidence for a
  protocol-translation proxy.

---

### Recommended Execution Order

| Step | Item | Risk | Prerequisite |
|------|------|------|-------------|
| 1 | ✅ B3 — `Session` enum | Low, isolated | — |
| 2 | ✅ B1 — `LogFormat` enum | Low, isolated | — |
| 3 | ✅ B4 — single SID source | Low | — |
| 4 | ✅ C2 — `Nrc::response_for` | Low | — |
| 4a | B5 — `UdsSid` typed enum | Low | — |
| 4b | B6 — `EcuAddress` / `DataIdentifier` newtypes | Low | — |
| 5 | ✅ D2 — Semaphore connection limit | Low, correctness fix | — |
| 6 | ✅ A3 — encapsulate `ServiceResolver` | Medium | — |
| 7 | ✅ A2 — `DiagHandler` trait | Medium | A3 |
| 8 | ✅ E1 — `MockDiagHandler` + DoIP tests | Medium | A2 |
| 9 | ✅ C1 — split `ConnectionHandler` | Large | A2, E1 |
| 10 | ✅ A4 — config slices | Medium | C1 |
| 11 | ✅ C3+C4 — `SovdMapper` cleanup | Small | — |
| 12 | A5 — adopt `opensovd-client` | Large | A4, C3 |
| 13 | D1 — token expiry | Small | A5 or C3 |
| 14 | E2 — extract mock gateway | Small | A5 or E1 |
| 15 | A1 — retire `doip-server` | Large | C1, E1 |
