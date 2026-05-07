<!--
SPDX-License-Identifier: Apache-2.0
SPDX-FileCopyrightText: 2026 The Contributors to Eclipse OpenSOVD (see CONTRIBUTORS)

See the NOTICE file(s) distributed with this work for additional
information regarding copyright ownership.

This program and the accompanying materials are made available under the
terms of the Apache License Version 2.0 which is available at
https://www.apache.org/licenses/LICENSE-2.0
-->

# Architecture & Developer Guide

This document is the authoritative reference for contributors. It explains
**what** exists, **why** the design looks the way it does, **how** to extend
it, and **what remains to be done**.

---

## 1. Crate Dependency Graph

```
            uds   ← zero dependency seam (thiserror + async-trait only)
           ↙         ↘
        doip          sovd  ← CDA + reqwest + serde live here
           ↘         ↙
             uds2sovd  ← binary: CLI, config, wiring
```

| Crate | Purpose | Key dependency |
|-------|---------|----------------|
| `uds` | UDS protocol primitives: `DiagHandler` trait, typed request structs, `UdsSid` enum, `DataIdentifier` newtype, `Nrc`, error types | `thiserror`, `async-trait` |
| `doip` | ISO 13400-2 DoIP TCP transport: accept connections, parse frames, route UDS to dispatcher | `tokio`, `uds` |
| `sovd` | ISO 22900-4 SOVD gateway integration: MDD resolver (CDA), REST client, `SovdDiagHandler` | `cda-*`, `reqwest`, `uds` |
| `uds2sovd` | Binary entry point: CLI (`clap`), TOML config, component wiring | all workspace crates |

### Dependency rules

- `uds` **must not** depend on `doip`, `sovd`, or any CDA crate.
- `doip` **must not** depend on `sovd` or any CDA crate.
- `sovd` **may not** depend on `doip` — they are peers under `uds`.
- Only `uds2sovd` wires them all together.

Enforcing these rules keeps each crate testable in isolation and prevents
CDA compile-time costs from polluting the transport layer.

---

## 2. Data Flow — Request Path

```
DoIP client (TCP)
     │
     │  [DoIP frame: routing activation, diagnostic request]
     ▼
ConnectionHandler  (doip/src/handler.rs)
     │  validates DoIP framing, checks routing activation state
     ▼
UdsDispatcher  (doip/src/uds_dispatcher.rs)
     │  validates UDS minimum length
     │  parses SID → UdsSid::try_from(sid)
     │  extracts DID → DataIdentifier::new(did)
     │  constructs typed request: ReadDid { did, raw } or WriteDid { did, raw }
     ▼
RequestHandler::handle(&dyn DiagHandler)  (uds/src/handler/mod.rs)
     │  visitor call: req.handle(backend) → backend.read_did(req)
     ▼
SovdDiagHandler  (sovd/src/diag_handler.rs)
     │  ServiceResolver::resolve() → ResolvedService
     │  SovdMapper::process_read_data_request()
     ▼
SovdGateway (trait)  (sovd/src/gateway.rs)
     │  Arc<dyn SovdGateway> — either SovdClient or MockSovdGateway
     │  SovdClient: HTTP GET/PATCH to SOVD gateway
     │  MockSovdGateway: synthetic MDD-driven response (no HTTP)
     ▼
SovdMapper::sovd_json_to_uds()  (sovd/src/mapper.rs)
     │  JSON → UDS byte encoding
     ▼
UDS positive/negative response bytes
     │  (returned back up the call stack)
     ▼
ConnectionHandler → DoIP diagnostic response frame → TCP client
```

---

## 3. Key Design Choices

### 3.1 Visitor Pattern for UDS Dispatch

**Problem**: How does the DoIP transport layer call the right `DiagHandler`
method without embedding a giant `match` in every handler implementation?

**Solution**: Each typed request struct (`ReadDid`, `WriteDid`) implements
`RequestHandler::handle(&dyn DiagHandler)` and calls the specific backend
method directly — no match needed in any backend:

```rust
// CORRECT — typed, no match in the handler
async fn read_did(&self, req: &ReadDid) -> Result<Vec<u8>> { … }
async fn write_did(&self, req: &WriteDid) -> Result<Vec<u8>> { … }

// WRONG — never do this in a DiagHandler
async fn handle_request(&self, raw: &[u8]) -> Result<Vec<u8>> {
    match raw[0] { … }   // match lives only in UdsDispatcher
}
```

The **one** match on request type lives in `impl RequestHandler for UdsRequest`
in `uds/src/handler/mod.rs`.  It is the auditable dispatch table.

### 3.2 `#[non_exhaustive]` Enum for Compile-time Service Completeness

`UdsRequest` is `#[non_exhaustive]` for a deliberate reason: adding a new UDS
service (`SessionControl`, `TesterPresent`, etc.) is a **compile-time breaking
change** that forces every match site in the codebase to be updated.  Because
there is only one match (the dispatch table), this means exactly one file must
be changed per new service — auditable and safe.

An alternative `Box<dyn RequestHandler>` open type would eliminate all match
expressions but lose the exhaustiveness guarantee.  For a safety-critical
automotive codebase, exhaustiveness is more valuable.

### 3.3 NewType Wrappers

| Type | Wraps | Why |
|------|-------|-----|
| `DataIdentifier(u16)` | raw DID `u16` | Prevents confusion with ECU logical addresses, port numbers, or other `u16` values at API boundaries |
| `EcuName(String)` | ECU name `String` | Prevents confusion with service names, endpoint paths, and gateway URLs; key in `HashMap<EcuName, Arc<ServiceResolver>>` |
| `GatewayUrl(String)` | SOVD base URL `String` | Cannot be accidentally passed as `ApiVersion` or `EcuName`; enforced by `SovdConfig` |
| `ApiVersion(String)` | SOVD API path segment `String` | Cannot be accidentally swapped with `GatewayUrl` in URL construction |
| `SovdEndpoint` | `(name, service_name, did)` | Bundles the three pieces that uniquely describe a SOVD operation — the URL segment, the MDD lookup key, and the DID for MUX disambiguation — so none can be forgotten or confused at call sites |
| `UdsSid` | SID `u8` | Typed dispatch via `TryFrom<u8>` — no raw byte comparisons in the dispatcher |

### 3.4 Crate-level Error Hierarchy

```
ProxyError  (uds — the seam, used workspace-wide)
  ├── Config(String)
  ├── Mdd(String)
  ├── Uds(UdsError)         ← InvalidLength { expected, actual }, InvalidDid(u16)
  ├── Sovd(SovdError)       ← Transport, HttpStatus { status, body },
  │                            Auth { status, body }, EndpointNotFound { endpoint },
  │                            SchemaMismatch { service, reason },
  │                            MetadataMissing { service }
  └── Io(std::io::Error)
```

All `SovdError` variants are **structured** (typed fields, no free-form string bags).
This means callers can match on `status`, `service`, and `reason` individually.
Library crates return `uds::error::Result<T>`.  The binary (`uds2sovd`) uses `anyhow`
for ergonomic top-level error reporting.

### 3.5 Async Stack

All async code uses `tokio` primitives exclusively.  The runtime is started
once in `uds2sovd/src/main.rs` with `#[tokio::main]`.  No blocking operations
may occur on the async executor; use `tokio::task::spawn_blocking` for any
synchronous I/O.

Interior mutability in async handlers: use `tokio::sync::Mutex` / `RwLock`,
not `std::sync::Mutex`, to avoid blocking the executor under contention.

---

## 4. Module Map

### `uds`

| File | Contains |
|------|----------|
| `src/lib.rs` | Crate-level docs and re-exports |
| `src/handler/mod.rs` | `UdsRequest` closed `#[non_exhaustive]` enum, `impl RequestHandler for UdsRequest` (the one dispatch table) |
| `src/handler/common.rs` | `DataIdentifier` newtype, `RequestHandler` trait |
| `src/handler/diag_handler.rs` | `DiagHandler` trait — one async method per UDS service |
| `src/handler/read_did.rs` | `ReadDid` struct + `impl RequestHandler` |
| `src/handler/write_did.rs` | `WriteDid` struct + `impl RequestHandler` |
| `src/error.rs` | `ProxyError`, `UdsError`, `SovdError`, `Nrc` |
| `src/uds_service_ids.rs` | SID constants + `UdsSid` enum with `TryFrom<u8>` / `From<UdsSid>` |

### `doip`

| File | Contains |
|------|----------|
| `src/lib.rs` | Re-exports: `DoIpServer`, `ConnectionHandler`, `DoIpMessage`, `ServerConfig`, `DoipConnectionConfig` |
| `src/server.rs` | `DoIpServer` — TCP listener, connection limit, task spawning |
| `src/handler.rs` | `ConnectionHandler` — single-connection state machine (routing activation → diagnostic messaging) |
| `src/session.rs` | `Session` — routing activation state machine |
| `src/uds_dispatcher.rs` | `UdsDispatcher` — SID routing, length validation, NRC construction |
| `src/message.rs` | `DoIpMessage` — DoIP wire-format framing |
| `src/config.rs` | `ServerConfig`, `DoipConnectionConfig` |

### `sovd`

| File | Contains |
|------|----------|
| `src/lib.rs` | Re-exports |
| `src/config.rs` | `GatewayUrl`, `ApiVersion`, `SovdEndpoint`, `EcuName`, `EcuConfig`, `SovdConfig` |
| `src/gateway.rs` | `SovdGateway` trait — the seam between mapper and any backend |
| `src/client/mod.rs` | `SovdClient` — HTTP implementation of `SovdGateway`; URL builders, token cache |
| `src/client/auth.rs` | `AuthRequest`, `AuthResponse` — OAuth2 wire types (private to `client/`) |
| `src/mock/mod.rs` | `MockSovdGateway` — MDD-driven implementation of `SovdGateway`; zero HTTP |
| `src/mock/generate.rs` | `generate_mock_response_data` and helpers (private to `mock/`) |
| `src/mapper.rs` | `SovdMapper` — UDS ↔ SOVD REST translation; holds `Arc<dyn SovdGateway>` |
| `src/diag_handler.rs` | `SovdDiagHandler` implements `DiagHandler` |
| `src/schema.rs` | SOVD REST response types (`DataResponse`, serde structs) |
| `src/resolver/mod.rs` | `ServiceResolver` — MDD-backed DID resolution (facade over CDA) |
| `src/resolver/resolve.rs` | `DidResolver`, `ResolvedService`, `ServiceType` |
| `src/resolver/metadata.rs` | `MetadataProvider` — MDD metadata queries |
| `src/resolver/response.rs` | `ResponseEncoder` — SOVD JSON → UDS bytes |
| `src/resolver/uds_helpers.rs` | `find_mux_case_prefix` and related helpers |

### `uds2sovd`

| File | Contains |
|------|----------|
| `src/main.rs` | CLI, config loading, `load_mdd`, component wiring, graceful shutdown |
| `src/config.rs` | `Config`, `LoggingConfig`, `LogFormat` |
| `examples/` crate | Runnable examples showing handler usage with a custom `DiagHandler` |

---

## 5. Adding a New UDS Service (Step-by-Step)

Example: adding `TesterPresent` (SID `0x3E`).

### 5.1 `uds/src/handler/`

Create `uds/src/handler/tester_present.rs` with the request struct and its impl:

```rust
pub struct TesterPresent {
    pub sub_function: u8,
    pub raw: Vec<u8>,
}

#[async_trait::async_trait]
impl RequestHandler for TesterPresent {
    async fn handle(&self, backend: &dyn DiagHandler) -> Result<Vec<u8>> {
        backend.tester_present(self).await
    }
}
```

Add `pub mod tester_present;` and `pub use tester_present::TesterPresent;` to
`uds/src/handler/mod.rs`.

Add a method to `DiagHandler` in `uds/src/handler/diag_handler.rs`
(the compiler flags all implementors):

```rust
async fn tester_present(&self, req: &TesterPresent) -> Result<Vec<u8>>;
```

Add a variant to `UdsRequest` in `uds/src/handler/mod.rs`
(the compiler flags the one dispatch match):

```rust
pub enum UdsRequest {
    ReadDid(ReadDid),
    WriteDid(WriteDid),
    TesterPresent(TesterPresent),   // ← new
}
```

Update the dispatch match in `impl RequestHandler for UdsRequest`:

```rust
Self::TesterPresent(r) => r.handle(backend).await,
```

### 5.2 `uds/src/uds_service_ids.rs`

`UdsSid::TesterPresent` already exists.  No change needed.

### 5.3 `doip/src/uds_dispatcher.rs`

Add a `handle_tester_present` method and a `UdsSid::TesterPresent` arm in
`dispatch()`:

```rust
Ok(UdsSid::TesterPresent) => self.handle_tester_present(&uds_msg).await,
```

### 5.4 `sovd/src/diag_handler.rs`

Implement `tester_present` on `SovdDiagHandler`.

### 5.5 Tests

- Unit test in `uds_dispatcher.rs` covering: valid request → positive response,
  missing sub-function → NRC 0x13, suppress-response sub-function → empty vec.
- Unit test in `diag_handler.rs` covering the SOVD path.

---

## 6. Testing Strategy

### 6.1 Unit Tests (in-file `#[cfg(test)]`)

Every module with business logic has a `mod tests` block.  Key invariants:

- `UdsDispatcher` tests: every SID arm, every length error path, every NRC.
- `UdsMessage` tests: parse, DID extraction, NRC frame construction.
- `DataIdentifier` tests: round-trip, display, From<u16>.
- `UdsSid` tests: `TryFrom` round-trip, unknown byte error.
- `Nrc` tests: wire byte, frame construction.
- `SovdMapper` tests: mock mode write, too-short request error.
- `SovdDiagHandler` tests: no managers → MDD error.

### 6.2 Integration / Example Tests

`examples/` crate contains `#[cfg(test)]` tests
that run against the custom handler in-process (no TCP, no SOVD gateway).
These cover:

- Positive read/write paths.
- Unknown-DID rejection.
- `CountingHandler` interior mutability.
- Security: handler receives typed structs, not raw bytes.

### 6.3 Coverage Goals

| Module | Target |
|--------|--------|
| `uds` (all) | 100% line/branch |
| `doip/uds_dispatcher` | 100% line/branch |
| `doip/handler` | ≥80% line |
| `sovd/mapper` | ≥80% line |
| `sovd/diag_handler` | ≥80% line |

Run coverage with `cargo-llvm-cov` (not yet wired into CI — see #8):

```sh
cargo llvm-cov --all-features --workspace --html
```

### 6.4 What Is NOT Tested

- CDA `ServiceResolver` (the CDA library is external; its behaviour is tested
  by the CDA project).  Only the facade (`resolver/mod.rs`) is unit-tested.
- SOVD HTTP client against a live gateway (integration tests require a running
  SOVD server; mock mode covers the happy path in unit tests).
- DoIP framing at the wire level (framing is owned by `doip/src/handler.rs`;
  property-based / fuzz tests are planned — see #8).

---

## 7. Security Properties

### 7.1 Input Validation Boundary

All untrusted bytes enter at `ConnectionHandler::handle_incoming_data`.  The
path to `DiagHandler` is:

```
&[u8] (network)
  → UdsDispatcher::dispatch (length check, SID parse)
  → DataIdentifier::new (u16 construction, no invariants to violate)
  → ReadDid / WriteDid (plain struct, no unsafe)
  → DiagHandler::read_did / write_did (typed, no raw bytes)
```

No raw byte slice reaches a `DiagHandler` implementation.  A malicious payload
can produce at most:

- An NRC response (shortest happy path for the attacker).
- A `ProxyError` (caught by the dispatcher, converted to NRC).

### 7.2 What the API Prevents

| Attack | Why it can't work |
|--------|------------------|
| Raw SID injection via `DiagHandler` | `DiagHandler` methods accept typed structs, never `&[u8]` |
| Integer overflow on length fields | `uds_dispatcher` uses checked slice indexing and guards |
| Panic in protocol path | All `unwrap`/`expect` in production paths are forbidden; CI enforces this via `clippy::unwrap_in_result` (planned) |
| Second async runtime | `async-trait` + `tokio` only; no `block_on` in library code |
| Sensitive data logging | Log messages never include ECU credentials, OAuth2 tokens, or raw MDD data |

### 7.3 Known Risks (tracked)

| Risk | Status | Mitigation |
|------|--------|-----------|
| `rsa` crate Marvin side-channel (RUSTSEC-2023-0071) | Suppressed | Indirect via CDA — proxy never calls RSA directly; blocked on CDA updating `jsonwebtoken` |
| `flatbuffers` personal fork | Tracked | Blocked on CDA upstream fix; never update `flatbuffers` without CDA |

---

## 8. What Is Done and What Is Pending

### Done ✅

- [x] Workspace restructure: `uds`, `doip`, `sovd`, `uds2sovd`
- [x] Visitor pattern dispatch: `RequestHandler` + typed request structs + `DiagHandler` per-service methods
- [x] `UdsRequest` closed `#[non_exhaustive]` enum — one auditable dispatch table
- [x] `DataIdentifier(u16)` newtype — propagated throughout
- [x] `EcuName(String)` newtype — propagated throughout
- [x] `GatewayUrl`, `ApiVersion` newtypes — SOVD config strings hardened
- [x] `SovdEndpoint` newtype — bundles URL segment + MDD service name + DID so none can be omitted or confused
- [x] `SovdError` — structured typed variants replacing free-form string bags
- [x] `SovdGateway` trait (`sovd/src/gateway.rs`) — clean seam with no CDA types in the signature
- [x] `SovdClient` moved to `sovd/src/client/` (HTTP-only, no mock logic)
- [x] `MockSovdGateway` moved to `sovd/src/mock/` (MDD-driven, no HTTP)
- [x] `MockSovdGateway` injects `Arc<ServiceResolver>` at construction — no per-call resolver passing
- [x] `SovdMapper` holds `Arc<dyn SovdGateway>` — no runtime branching inside mapper
- [x] `uds/src/handler/` split into per-service files (`common.rs`, `diag_handler.rs`, `read_did.rs`, `write_did.rs`, `mod.rs`)
- [x] `UdsSid` typed enum with `TryFrom<u8>` — dispatcher uses typed match
- [x] All compiler warnings fixed (zero warnings on stable 1.88.0)
- [x] All pedantic Clippy lints pass (`-D warnings -W clippy::pedantic`)
- [x] 175 unit tests passing
- [x] `doc_markdown` lints: DoIP, OAuth2 in backticks
- [x] `README.md` and `.github/copilot-instructions.md` updated to new crate names
- [x] Example app: `examples/` crate
- [x] Sample files: `examples/mdd/FLXCNG1000.mdd`, `examples/config.toml` (removed hardcoded defaults from CLI)
- [x] Comprehensive doctests on all public types in `uds`
- [x] `ARCHITECTURE.md` (this file)

### Pending ❌

#### High priority (blocks correctness)

- [ ] **`TesterPresent` (SID 0x3E) support** — required for UDS session keepalive; currently returns NRC 0x11 (ServiceNotSupported). Needs `TesterPresent` request struct, `DiagHandler::tester_present`, `UdsRequest::TesterPresent`, dispatcher arm.
- [ ] **`DiagnosticSessionControl` (SID 0x10) support** — required to switch ECU diagnostic session mode.  Needs `SessionControl` request struct + SOVD gateway mode API integration.

#### Medium priority (quality / completeness)

- [ ] **`cargo-llvm-cov` in CI** — coverage gating to enforce table in #6.3.
- [ ] **Property-based / fuzz tests for DoIP framing** — `cargo-fuzz` target for `ConnectionHandler` and `UdsDispatcher` using arbitrary byte slices.
- [ ] **`clippy::unwrap_in_result`** lint enabled — currently only `clippy::pedantic`; add `clippy::restriction` subset for panic-safety.
- [ ] **`cargo deny check` in CI** — currently only run locally.
- [ ] **Structured NRC telemetry** — emit `tracing` spans with DID, SID, NRC code for observability.
- [ ] **Multiple ECU support** — dispatcher currently selects first resolver if named ECU not found; should route by DoIP logical address.

#### Low priority / future work

- [ ] **DoIP routing-activation authentication** — currently accepts all routing activation requests.
- [ ] **ISO 14229 service expansion** — `InputOutputControlByIdentifier` (0x2F), `RoutineControl` (0x31), `ReadDTCInformation` (0x19).
- [ ] **SOVD schema versioning** — currently hard-coded `v15`; should negotiate from gateway capability response.
- [ ] **Hot-reload MDD** — reload MDD without restarting the proxy.
- [ ] **Metrics endpoint** — Prometheus-compatible counters for requests/NRCs/latency.
- [ ] **`reuse lint` CI** — SPDX header enforcement; blocked on `LICENSES/Apache-2.0.txt` being committed.

---

## 9. Build & Check Reference

```sh
# Build
cargo build --locked --all-targets

# Tests
cargo test --locked

# Pedantic Clippy (zero warnings required)
cargo clippy --all-targets --all-features -- -D warnings -W clippy::pedantic

# Nightly formatting check
cargo +nightly fmt -- --check \
  --config error_on_unformatted=true,error_on_line_overflow=true,\
format_strings=true,group_imports=StdExternalCrate,imports_granularity=Crate

# Dependency / license audit
cargo deny check

# Pre-commit hooks
pre-commit run --all-files
```
