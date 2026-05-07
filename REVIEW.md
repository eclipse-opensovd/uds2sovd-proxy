<!--
SPDX-License-Identifier: Apache-2.0
SPDX-FileCopyrightText: 2026 The Contributors to Eclipse OpenSOVD (see CONTRIBUTORS)

See the NOTICE file(s) distributed with this work for additional
information regarding copyright ownership.

This program and the accompanying materials are made available under the
terms of the Apache License Version 2.0 which is available at
https://www.apache.org/licenses/LICENSE-2.0
-->

# Code Quality Review — uds2sovd-proxy

**Date**: 2026-05-06  
**Reviewer**: GitHub Copilot (rust-safety-reviewer skill)  
**Scope**: Full workspace — every source file, every `Cargo.toml`, configuration and
  documentation file.  
**Toolchain**: stable 1.88.0 — verified clean build, 182 tests pass, zero pedantic
  Clippy warnings.

---

## Executive Summary

The codebase is at a **good structural quality level** for an early-stage open-source
project. The core protocol stack (`uds`, `doip`, `sovd`) is cleanly separated, typed
errors are consistent, async primitives are used correctly, and the recent refactoring
arc has removed the worst coupling and god-function smells. Tests pass and pedantic
Clippy is satisfied.

However several gaps remain that must be addressed before this proxy handles real
diagnostic sessions. The most critical are:

- A **protocol non-conformance** in the DoIP routing activation response (missing
  mandatory reserved bytes).
- A **hardcoded default secret** (`"test_secret"`) reachable in the production binary
  via config-load fallback.
- An **OAuth2 token that never expires** — any deployment running longer than the
  server-side JWT TTL (typically 15 min–1 hour) will silently fail.
- An **orphaned directory** (`proxy-main/`) that looks like active code but cannot be
  compiled.
- **Zero unit test coverage** of the MDD-backed resolver and metadata layers.

Items are ranked HIGH / MEDIUM / LOW and grouped into actionable sections with
concrete fix proposals.

---

## Priority Index

| # | Severity | Category | One-line description |
|---|---|---|---|
| [F-01](#f-01-routing-activation-response-missing-4-reserved-bytes) | **HIGH** | Protocol | Routing activation response is 5 bytes, must be ≥ 9 |
| [F-02](#f-02-hardcoded-default-secret-reachable-in-production) | **HIGH** | Security | `DEFAULT_CLIENT_SECRET = "test_secret"` reachable via config-load fallback |
| [F-03](#f-03-oauth2-token-never-refreshed) | **HIGH** | Reliability | OAuth2 token cached forever; no TTL, no re-auth on 401 |
| [F-04](#f-04-no-https-enforcement-on-gateway-url) | **HIGH** | Security | Default `http://` gateway; no validator enforces HTTPS |
| [F-05](#f-05-orphaned-proxy-main-directory) | **HIGH** | Maintainability | `proxy-main/` not in workspace; references non-existent crates |
| [F-06](#f-06-ecuname-doc-comment-formatting-defect) | **HIGH** | Documentation | `EcuName` `///` swallowed by `//` section separator |
| [F-07](#f-07-zero-unit-test-coverage-for-mdd-backed-layers) | **HIGH** | Testing | `ServiceResolver`, `MetadataProvider`, `DidResolver` are untestable in unit tests |
| [F-08](#f-08-tokio--full-in-library-crates) | **MEDIUM** | Dependencies | `tokio = { features = ["full"] }` in `doip` and `sovd` library crates |
| [F-09](#f-09-datareponse-errors-array-silently-ignored) | **MEDIUM** | Reliability | `DataResponse.errors[]` never actioned — wrong data returns as positive UDS |
| [F-10](#f-10-on²-deduplication-in-build_full_candidate_list) | **MEDIUM** | Performance | `Vec::contains` in O(n²) dedup loop in `build_full_candidate_list` |
| [F-11](#f-11-get_token-holds-mutex-across-http-round-trip) | **MEDIUM** | Performance | `Mutex` held for full HTTP call in `get_token` serialises all request threads |
| [F-12](#f-12-logginglevel-string-not-validated-at-config-load) | **MEDIUM** | Reliability | Log-filter string accepted without validation; bad values silently no-op |
| [F-13](#f-13-tester-present-and-session-control-not-dispatched) | **MEDIUM** | Protocol | 0x3E `TesterPresent` and 0x10 `DiagnosticSessionControl` not handled |
| [F-14](#f-14-no-connection-authentication-or-source-address-check) | **MEDIUM** | Security | Any TCP client on port 13400 can activate routing |
| [F-15](#f-15-missing-doc-comments-on-several-public-items) | **LOW** | Documentation | `MetadataProvider`, `DidResolver`, `ResolvedService` fields undocumented |
| [F-16](#f-16-dead-workspace-dependency-anyhow) | **LOW** | Dependencies | `anyhow` declared in workspace deps but no active crate uses it |
| [F-17](#f-17-repeated-cast-pattern-replace-with-to_be_bytes) | **LOW** | Style | 5× `#[allow(clippy::cast_possible_truncation)]` on identical shift/cast pattern |
| [F-18](#f-18-routing-activation-reserved-field-is-dead-code) | **LOW** | Maintainability | `RoutingActivationRequest::reserved` is parsed but never read |
| [F-19](#f-19-codestylemd-references-removed-module-path) | **LOW** | Documentation | `CODESTYLE.md` module map references `proxy-core/` which no longer exists |
| [F-20](#f-20-missing-round-trip-tests-for-udssid-enum) | **LOW** | Testing | No test exercises every `UdsSid` variant in `TryFrom<u8>` ↔ `From<UdsSid>` round-trip |

---

## Detailed Findings

---

### F-01 — Routing Activation Response Missing 4 Reserved Bytes

**Severity**: HIGH | **Category**: Protocol Conformance  
**File**: [doip/src/handler/routing.rs](doip/src/handler/routing.rs#L52-L65)

**Observation**

ISO 13400-2 §7.3.2 defines the routing activation response payload as:

| Offset | Length | Field |
|--------|--------|-------|
| 0 | 2 | Source address (tester logical address) |
| 2 | 2 | Logical address of DoIP entity |
| 4 | 1 | Routing activation response code |
| **5** | **4** | **Reserved (shall be 0x00000000)** |
| 9 | 4 | OEM-specific (set to 0x00000000 if unused) |

Minimum valid response: **9 bytes** (without OEM-specific). Maximum: **13 bytes**.

Current implementation sends only **5 bytes**. Any conformant diagnostic client that
validates the response length (e.g. ETAS INCA, Vector CANalyzer, ISO-14229-5 stack
implementations) will reject the activation and log a protocol error.

```rust
// CURRENT (doip/src/handler/routing.rs):
let mut payload = Vec::new();
payload.extend_from_slice(&req.source_address.to_be_bytes());       // 2 bytes
payload.extend_from_slice(&ctx.conn_config.ecu_logical_address.to_be_bytes()); // 2 bytes
payload.push(ROUTING_ACTIVATION_SUCCESS);                            // 1 byte  (total: 5)
```

**Proposed Fix**

```rust
/// Mandatory reserved field — shall be 0x00000000 per ISO 13400-2 §7.3.2.
const ROUTING_ACTIVATION_RESERVED: [u8; 4] = [0x00, 0x00, 0x00, 0x00];

// In handle():
let mut payload = Vec::new();
payload.extend_from_slice(&req.source_address.to_be_bytes());
payload.extend_from_slice(&ctx.conn_config.ecu_logical_address.to_be_bytes());
payload.push(ROUTING_ACTIVATION_SUCCESS);
payload.extend_from_slice(&ROUTING_ACTIVATION_RESERVED);  // ← add this line
```

**Testing**: update the existing `routing_activation_returns_success_response` test to
assert `response.payload.len() == 9` and that bytes 5–8 are all `0x00`.

---

### F-02 — Hardcoded Default Secret Reachable in Production

**Severity**: HIGH | **Category**: Security (OWASP A07 — Identification and Authentication Failures)  
**File**: [sovd/src/config.rs](sovd/src/config.rs#L30)

**Observation**

```rust
const DEFAULT_CLIENT_SECRET: &str = "test_secret";
```

This constant is used by `SovdConfig::default()`. The binary's `main()` falls back to
`Config::default()` when the config file fails to parse:

```rust
// uds2sovd/src/main.rs
let mut config = Config::from_file(&args.config).unwrap_or_else(|e| {
    eprintln!("Config load failed: {e}. Using defaults.");
    Config::default()
});
```

A deployment where the config file is missing or corrupted will authenticate to the SOVD
gateway with `client_id = "uds2sovd_proxy"` and `client_secret = "test_secret"`. If the
target gateway accepts these credentials, it is a silent security exposure.

**Proposed Fixes**

1. **Short term**: Do not fall back on parse failure. Return an error and exit:

   ```rust
   let config = Config::from_file(&args.config)
       .with_context(|| format!("Failed to load config from '{}'", args.config.display()))?;
   ```

2. **Medium term**: Remove `SovdConfig::Default` entirely, or ensure `default()` panics with
   a clear message indicating it must not be used outside tests. Use
   `#[cfg(test)]` to restrict the default impl.

3. **Long term**: Never store credentials in application defaults. Require credentials via
   environment variables or a secrets manager, validated on startup.

---

### F-03 — OAuth2 Token Never Refreshed

**Severity**: HIGH | **Category**: Reliability / Security  
**File**: [sovd/src/client/mod.rs](sovd/src/client/mod.rs#L180)

**Observation**

`get_token()` fetches a token on first call and caches it forever in
`Arc<Mutex<Option<String>>>`. There is no TTL check and no re-authentication on
`401 Unauthorized`. A typical OAuth2 JWT has a server-side lifetime of 15 minutes to
1 hour. After expiry:

- All SOVD reads and writes return `SovdError::HttpStatus(401)`.
- The proxy continues to serve DoIP connections but every UDS diagnostic response will
  be a negative response `0x22 (ConditionsNotCorrect)` or `0x72 (GeneralProgrammingFailure)`.
- No operator alert is raised. The proxy appears to be running correctly.

**Proposed Fix**

Cache the token with its expiry timestamp. On each `get_token()` call, treat any token
expiring within a safety margin (e.g. 30 seconds) as absent, triggering a fresh fetch.

```rust
use std::time::{Duration, Instant};

struct CachedToken {
    token: String,
    expires_at: Instant,
}

// In SovdClient:
access_token: Arc<Mutex<Option<CachedToken>>>,

// In get_token():
let mut guard = self.access_token.lock().await;
let refresh_margin = Duration::from_secs(30);
if let Some(cached) = guard.as_ref() {
    if cached.expires_at > Instant::now() + refresh_margin {
        return Ok(cached.token.clone());
    }
}
// cached is missing or expiring soon — fetch fresh
let (token, expires_in) = self.fetch_fresh_token().await?;
*guard = Some(CachedToken {
    token: token.clone(),
    expires_at: Instant::now() + Duration::from_secs(expires_in.saturating_sub(30)),
});
Ok(token)
```

Requires `AuthResponse` to expose `expires_in: u64` (standard OAuth2 field). If the
SOVD server does not return `expires_in`, use a conservative 10-minute default.

Also add: re-authentication on `401` in `read_data` / `write_data` before propagating
the error (retry once with a fresh token).

---

### F-04 — No HTTPS Enforcement on Gateway URL

**Severity**: HIGH | **Category**: Security (OWASP A02 — Cryptographic Failures)  
**File**: [sovd/src/config.rs](sovd/src/config.rs#L28)

**Observation**

The default gateway URL is `http://localhost:20002` and the validator
`deserialize_nonempty_gateway_url` only checks that the field is non-empty — it does not
require an HTTPS scheme. OAuth2 tokens and full UDS diagnostic payloads travel in
plaintext over any HTTP deployment.

**Proposed Fix**

Add a scheme check in the validator:

```rust
fn deserialize_nonempty_gateway_url<'de, D>(d: D) -> Result<GatewayUrl, D::Error>
where
    D: Deserializer<'de>,
{
    let raw = String::deserialize(d)?;
    if raw.trim().is_empty() {
        return Err(de::Error::custom("gateway_url must not be empty"));
    }
    // Warn — not error — to allow localhost HTTP in development.
    if !raw.starts_with("https://") {
        tracing::warn!(
            "gateway_url '{}' uses plain HTTP; OAuth2 tokens will be sent unencrypted. \
             Set gateway_url to an https:// address in production.",
            raw
        );
    }
    Ok(GatewayUrl(raw))
}
```

For production deployments, consider making HTTP a hard error controlled by a
`--allow-insecure` CLI flag.

---

### F-05 — Orphaned `proxy-main/` Directory

**Severity**: HIGH | **Category**: Maintainability / Contributor Experience  
**File**: [proxy-main/](proxy-main/)

**Observation**

`proxy-main/` exists on disk but is **not listed in `[workspace.members]`**. Its
`Cargo.toml` references three workspace crates (`proxy-core`, `proxy-doip`, `proxy-sovd`)
that do not exist in the workspace. It uses a completely different API surface (`DiagHandler`,
`SovdClient`, `DoIpServer`) from different import paths. It cannot be built, is not tested,
and does not reflect the current architecture.

A contributor browsing the repository will find this directory and may reasonably conclude
it is part of the active codebase.

**Proposed Fix**

Delete the directory and record the deletion in a commit:

```
chore: remove orphaned proxy-main/ skeleton

proxy-main/ references workspace crates (proxy-core, proxy-doip, proxy-sovd)
that no longer exist. The active binary is uds2sovd/. Removing to prevent
contributor confusion.
```

If the files have historical value, archive them in a `legacy/` branch or tag before
deletion.

---

### F-06 — `EcuName` Doc Comment Formatting Defect

**Severity**: HIGH | **Category**: Documentation  
**File**: [sovd/src/config.rs](sovd/src/config.rs#L183)

**Observation**

Line 183 reads (collapsed to a single line by the formatter):

```
// ── EcuName ───────────────────────────────────────────────────────────────────/// Typed ECU identifier...
```

The `///` doc comment is appended to the `//` section separator on the same line, making it
part of the regular comment. The Rust compiler ignores it. `EcuName` has **no effective doc
comment** on the struct itself, despite the intent being clear. `missing_docs` is disabled
workspace-wide so no warning fires.

**Proposed Fix**

Insert a newline between the section separator and the doc comment:

```rust
// ── EcuName ───────────────────────────────────────────────────────────────────

/// Typed ECU identifier used as a SOVD component path segment and MDD lookup key.
///
/// ...
#[derive(Debug, Clone, PartialEq, Eq, Hash, Deserialize)]
pub struct EcuName(String);
```

This same pattern should be audited across all section separators in `config.rs`.

---

### F-07 — Zero Unit Test Coverage for MDD-Backed Resolver Layers

**Severity**: HIGH | **Category**: Testing  
**Files**: [sovd/src/resolver/mod.rs](sovd/src/resolver/mod.rs),
[sovd/src/resolver/metadata.rs](sovd/src/resolver/metadata.rs),
[sovd/src/resolver/resolve.rs](sovd/src/resolver/resolve.rs)

**Observation**

`ServiceResolver::new`, `DidResolver::resolve`, `MetadataProvider::get_*`, and
`ResponseEncoder::build_response` all require a live `ManagerHandle`
(`Arc<RwLock<CdaEcuManager<DefaultSecurityPluginData>>>`) which in turn requires a real
MDD binary file loaded by `DiagnosticDatabase::new(path)`. No unit test can exercise any
of these code paths without a real MDD file — which is not checked into the repository.

This leaves the entire translation pipeline (the core value of the proxy) with zero
automated verification in the CI matrix.

**Proposed Fixes**

**Option A (recommended): dependency-injection seam**  
Extract a `trait EcuManagerProvider`:

```rust
/// Provides ECU manager access for MDD-backed metadata queries.
///
/// Implemented by the CDA-backed live provider and a test double.
#[cfg_attr(test, mockall::automock)]
#[async_trait::async_trait]
pub(crate) trait EcuManagerProvider: Send + Sync {
    async fn get_response_metadata(&self, service: &str) 
        -> Result<Vec<cda_interfaces::ResponseParameterInfo>>;
    async fn get_request_metadata(&self, service: &str) 
        -> Result<Vec<cda_interfaces::RequestParameterInfo>>;
    // … etc.
}
```

Replace `ManagerHandle` with `Arc<dyn EcuManagerProvider>` in `MetadataProvider`.
The live `CdaManagerProvider` wraps the `RwLock<CdaEcuManager>`. Tests inject a `MockEcuManagerProvider`.

**Option B (interim): seam at `ServiceResolver`**  
Add a test constructor `ServiceResolver::new_with_mock(manager: ManagerHandle)` and check
in a small synthetic MDD fixture binary (< 2 MiB limit) under `testdata/`.

**Regardless of approach**: the CI matrix must cover `cargo test --locked` on the full
resolver round-trip (RDBI request → SOVD JSON → UDS response bytes) with at least one
known DID fixture.

---

### F-08 — `tokio = { features = ["full"] }` in Library Crates

**Severity**: MEDIUM | **Category**: Dependencies  
**Files**: [doip/Cargo.toml](doip/Cargo.toml#L23), [sovd/Cargo.toml](sovd/Cargo.toml)

**Observation**

`"full"` enables every Tokio subsystem: `fs`, `process`, `signal`, `net`, `io`,
`rt-multi-thread`, `time`, `sync`, `macros`. Library crates `doip` and `sovd` do not use
`fs`, `process`, or `signal`. This inflates compile times, increases the dependency attack
surface, and misleads consumers about what the library actually needs.

The workspace guideline states: "enable only features your crate actually uses".

**Proposed Fix**

`doip` needs: `net`, `io`, `sync`, `rt`, `macros`, `time`  
`sovd` needs: `sync`, `rt`, `macros`, `time`

```toml
# doip/Cargo.toml
tokio = { workspace = true, features = ["net", "io-util", "sync", "rt", "macros", "time"] }

# sovd/Cargo.toml
tokio = { workspace = true, features = ["sync", "rt", "macros", "time"] }
```

Verify `cargo build --locked --all-targets` still passes after narrowing. Add a comment
documenting why each feature is needed.

---

### F-09 — `DataResponse.errors[]` Silently Ignored

**Severity**: MEDIUM | **Category**: Reliability / Protocol Correctness  
**File**: [sovd/src/mapper.rs](sovd/src/mapper.rs#L40), [sovd/src/schema.rs](sovd/src/schema.rs)

**Observation**

`DataResponse` has an `errors: Vec<SovdError>` field (tracked by `TODO(sovd-server)`).
When the SOVD server returns field-level errors (e.g. access denied on a specific data
item), the `errors` array is populated but never inspected. `process_read_data_request`
proceeds to call `sovd_json_to_uds` on whatever `data` is present, potentially returning
a positive UDS response (`0x62 RDBI`) with missing or default-valued fields.

**Proposed Fix**

In `process_read_data_request`, check `errors` before encoding:

```rust
if !response.errors.is_empty() {
    let detail: String = response.errors.iter()
        .map(|e| format!("{e}"))
        .collect::<Vec<_>>()
        .join("; ");
    tracing::warn!("[SOVD] Server returned field errors: {}", detail);
    return Err(ProxyError::Sovd(SovdError::FieldError(detail)));
}
```

Map `SovdError::FieldError` to `Nrc::ConditionsNotCorrect` (0x22) in `uds_dispatcher.rs`.

---

### F-10 — O(n²) Deduplication in `build_full_candidate_list`

**Severity**: MEDIUM | **Category**: Performance  
**File**: [sovd/src/resolver/resolve.rs](sovd/src/resolver/resolve.rs)

**Observation**

```rust
for dc in prefix_matches {
    let name = dc.lookup_name.as_deref().unwrap_or(&dc.name).to_owned();
    if !candidates.contains(&name) {  // O(n) for each item
        candidates.push(name);
    }
}
```

`Vec::contains` is O(n) per call. With n items in `prefix_matches` plus m items in
`extra_names`, total work is O((n+m)²). MDD databases with hundreds of services will
degrade noticeably.

**Proposed Fix**

Use a `HashSet<String>` as a seen-set:

```rust
let mut seen = std::collections::HashSet::new();
let mut candidates: Vec<String> = Vec::new();

for dc in prefix_matches {
    let name = dc.lookup_name.as_deref().unwrap_or(&dc.name).to_owned();
    if seen.insert(name.clone()) {
        candidates.push(name);
    }
}
// same for extra_names
```

This reduces to O(n+m) total.

---

### F-11 — `get_token` Holds `Mutex` Across HTTP Round-Trip

**Severity**: MEDIUM | **Category**: Performance / Throughput  
**File**: [sovd/src/client/mod.rs](sovd/src/client/mod.rs#L190)

**Observation**

```rust
async fn get_token(&self) -> Result<String> {
    let mut guard = self.access_token.lock().await;  // ← acquired
    if let Some(token) = guard.as_ref() {
        return Ok(token.clone());
    }
    let token = self.fetch_fresh_token().await?;     // ← HTTP call while locked
    *guard = Some(token.clone());
    Ok(token)
}
```

While this correctly prevents the TOCTOU race (see session context), holding a `Mutex`
across an async HTTP call (which can take hundreds of milliseconds or timeout at 5 seconds)
means **all concurrent requests are serialized** behind the lock until the token is
populated. In a real vehicle diagnostic session with multiple simultaneous SOVD calls, this
creates a stall.

**Proposed Fix**

Use `tokio::sync::OnceCell` for a true one-shot initialization, or a
`tokio::sync::watch::Receiver<Option<String>>` pattern where the sender writes once and
all waiters unblock. For the token-refresh case (F-03), a `watch` channel is the right
primitive:

```rust
use tokio::sync::watch;

// Field:
token_tx: watch::Sender<Option<CachedToken>>,
token_rx: watch::Receiver<Option<CachedToken>>,

// get_token():
// If current token is valid, return it immediately (no lock held).
// If expired, use a separate refresh Mutex to ensure only one refresher.
```

This eliminates the stall for the common case (valid cached token), while still
preventing concurrent refresh storms.

---

### F-12 — Log-Level String Not Validated at Config Load

**Severity**: MEDIUM | **Category**: Reliability / Operator Experience  
**File**: [uds2sovd/src/config.rs](uds2sovd/src/config.rs)

**Observation**

`LoggingConfig.level: String` is passed directly to `tracing_subscriber::EnvFilter`.
An invalid filter directive (e.g. `level = "infoo"` in the TOML) silently falls back
to the default filter or produces no output. No error is logged at startup. The operator
has no indication that the log level they set is not in effect.

**Proposed Fix**

Validate at config-load time:

```rust
use tracing_subscriber::filter::EnvFilter;

impl LoggingConfig {
    pub fn validated_filter(&self) -> Result<EnvFilter, String> {
        EnvFilter::try_new(&self.level)
            .map_err(|e| format!("Invalid log level '{}': {e}", self.level))
    }
}
```

Call this in `init_logging` and emit an error (falling back to `INFO`) if invalid.

---

### F-13 — `TesterPresent` and `DiagnosticSessionControl` Not Dispatched

**Severity**: MEDIUM | **Category**: Protocol Compliance  
**File**: [doip/src/uds_dispatcher.rs](doip/src/uds_dispatcher.rs)

**Observation**

UDS 0x3E (`TesterPresent`) is required to keep an ECU in a non-default diagnostic session.
If an external tool establishes a non-default session (e.g. programming session 0x02) and
then this proxy forwards a RDBI/WDBI request, the ECU may time out back to the default
session before the proxy sends its own 0x3E keepalive, causing the request to fail with
`NRC 0x22 ConditionsNotCorrect`.

UDS 0x10 (`DiagnosticSessionControl`) responses from the ECU contain the `P2` and `P2*`
server timing parameters. Not parsing these means the proxy always uses the hardcoded
timeout rather than ECU-reported values.

**Proposed Fix**

For `TesterPresent` (0x3E):
- Pass-through to the ECU when received from the tester (zero sub-function byte only, no
  response required). Add a handler that returns an appropriate positive response locally
  if suppress-response bit is not set.

For `DiagnosticSessionControl` (0x10):
- Parse the positive response and extract `P2ServerMax` / `P2StarServerMax` values.
- Store in `Session` and use them as the timeout cap for subsequent request handling.

Both can be tracked as GitHub issues with references to ISO 14229-1 §9.2 and §10.4.

---

### F-14 — No Connection Authentication or Source Address Validation

**Severity**: MEDIUM | **Category**: Security  
**File**: [doip/src/handler/routing.rs](doip/src/handler/routing.rs)

**Observation**

`RoutingActivationHandler` accepts any `source_address` from any TCP client without
authentication. ISO 13400-2 §7.3.2 defines an optional `OEM-specific` field and the
`PENDING_FOR_EXTERNAL_CONFIRMATION (0x10)` response code for implementations that require
authentication before activating routing.

Any host that can reach TCP port 13400 can activate routing and inject arbitrary UDS
diagnostic messages into the ECU. In a production vehicle network this is equivalent to
unrestricted OBD access.

**Proposed Fix** (short-term)

Implement a source-address allowlist in `DoipConnectionConfig`:

```rust
/// IP addresses or CIDR ranges allowed to activate DoIP routing.
/// Empty list means unrestricted (development / test only).
#[serde(default)]
pub allowed_tester_addresses: Vec<std::net::IpAddr>,
```

In `RoutingActivationHandler`, check `ctx.peer_addr` against the allowlist and return
`RoutingActivationDenied (0x00)` if rejected.

---

### F-15 — Missing Doc Comments on Several Public Items

**Severity**: LOW | **Category**: Documentation

| Item | File |
|---|---|
| `MetadataProvider` struct | [sovd/src/resolver/metadata.rs](sovd/src/resolver/metadata.rs) |
| `MetadataProvider::manager_handle()` | [sovd/src/resolver/metadata.rs](sovd/src/resolver/metadata.rs) |
| `DidResolver` struct | [sovd/src/resolver/resolve.rs](sovd/src/resolver/resolve.rs) |
| `DidResolver::new` | [sovd/src/resolver/resolve.rs](sovd/src/resolver/resolve.rs) |
| `ResolvedService.params` field | [sovd/src/resolver/resolve.rs](sovd/src/resolver/resolve.rs) |
| `RoutingActivationHandler` struct | [doip/src/handler/routing.rs](doip/src/handler/routing.rs) |
| `DiagnosticMessageHandler` struct | [doip/src/handler/diagnostic.rs](doip/src/handler/diagnostic.rs) |
| `LoggingConfig` field level/format | [uds2sovd/src/config.rs](uds2sovd/src/config.rs) |

**Proposed Fix**: add `///` doc comments to each. Strongly consider enabling
`#![warn(missing_docs)]` at the workspace or crate level to catch future gaps automatically.

---

### F-16 — Dead Workspace Dependency: `anyhow`

**Severity**: LOW | **Category**: Dependencies  
**File**: [Cargo.toml](Cargo.toml)

**Observation**

`anyhow = { version = "1.0", default-features = false }` is declared in
`[workspace.dependencies]` but no active workspace member uses it. The only consumer is
the orphaned `proxy-main/` (tracked in F-05). Dead entries in `[workspace.dependencies]`
mislead contributors and inflate `Cargo.lock`.

**Proposed Fix**: remove the `anyhow` entry from `[workspace.dependencies]` after
deleting `proxy-main/` (F-05).

---

### F-17 — Repeated Shift/Cast Pattern — Use `to_be_bytes()`

**Severity**: LOW | **Category**: Code Style  
**File**: [sovd/src/resolver/resolve.rs](sovd/src/resolver/resolve.rs)

**Observation**

Five instances of the pattern:

```rust
#[allow(clippy::cast_possible_truncation)]
let resolved = Some(*cv as u16);
```

and:

```rust
// f64 -> u16 narrowing is safe for DID range (0x0000-0xFFFF).
#[allow(clippy::cast_possible_truncation)]
```

Where a `u16` DID is decomposed into bytes using `(did >> 8) as u8` and `(did & 0xFF) as u8`.

**Proposed Fix**

Replace with `did.to_be_bytes()`:

```rust
// Before:
let [hi, lo] = [(did >> 8) as u8, (did & 0xFF) as u8];

// After:
let [hi, lo] = did.to_be_bytes();
```

This eliminates all five `#[allow(clippy::cast_possible_truncation)]` annotations, is
self-documenting, and cannot be wrong.

---

### F-18 — `RoutingActivationRequest::reserved` Is Dead Code

**Severity**: LOW | **Category**: Maintainability  
**File**: [doip/src/message.rs](doip/src/message.rs)

**Observation**

```rust
/// OEM-specific reserved field.
#[allow(dead_code)] // TODO(doip): Use for OEM-specific routing activation handling
pub reserved: u32,
```

The field is parsed from the wire but never read. The `#[allow(dead_code)]` + TODO
combination is a smell: either the field should be used (define an `ActivationType` enum
and `OemSpecific` handling) or it should be removed.

**Proposed Fix** (short-term): remove the field and the `allow` until OEM-specific handling
is designed. The TODO should live in `TODO.md`, not in production source code.

---

### F-19 — `CODESTYLE.md` Module Map References Removed Path

**Severity**: LOW | **Category**: Documentation  
**File**: [CODESTYLE.md](CODESTYLE.md)

**Observation**

`CODESTYLE.md` contains a "Module Map" section referencing `proxy-core/src/service_resolver/`
— a path that no longer exists following the crate reorganisation. The authoritative module
map is now in `ARCHITECTURE.md`.

**Proposed Fix**: update `CODESTYLE.md` to remove the stale module map or point readers to
`ARCHITECTURE.md`. Add a CI check (e.g. a `pre-commit` hook using `check-links`) to detect
stale internal path references.

---

### F-20 — No Round-Trip Tests for `UdsSid` Enum

**Severity**: LOW | **Category**: Testing  
**File**: [uds/src/lib.rs](uds/src/lib.rs)

**Observation**

`UdsSid` has `TryFrom<u8>` and `From<UdsSid> for u8`. Adding a new variant requires updating
both arms manually. There are no tests that exercise every variant in both directions. A
missing arm in `From<UdsSid>` would cause a Clippy error today (non-exhaustive match), but
a missing arm in `TryFrom<u8>` would silently return `Err` for a valid SID.

**Proposed Fix**

```rust
#[test]
fn udssid_round_trips_for_all_known_variants() {
    let variants = [
        UdsSid::ReadDataByIdentifier,
        UdsSid::WriteDataByIdentifier,
        // … all variants
    ];
    for v in variants {
        let byte = u8::from(v);
        assert_eq!(UdsSid::try_from(byte), Ok(v),
            "Round-trip failed for {:?}", v);
    }
}
```

---

## Non-Technical Quality Assessment

### Project Infrastructure

| Dimension | Rating | Notes |
|---|---|---|
| CI/CD completeness | **Good** | Build, test, Clippy (pedantic), rustfmt (nightly), deny check, pre-commit all gated |
| License compliance | **Good** | SPDX headers on all source files, `deny.toml` with explicit license allowlist |
| Dependency audit | **Good** | `cargo-deny` configured with advisory tracking |
| Commit hygiene | **Good** | Conventional Commits format documented in `copilot-instructions.md` |
| Contributor guidance | **Good** | `CONTRIBUTING.md`, `CODESTYLE.md`, `ARCHITECTURE.md` all present |
| DCO / ECA sign-off | **Required** | Eclipse CLA requirement — must be enforced in CI |
| `TODO.md` maintenance | **Good** | Known gaps tracked with priority symbols; referenced from source TODOs |

### Architecture

| Dimension | Rating | Notes |
|---|---|---|
| Crate boundary design | **Good** | `uds` ← `doip` ← `sovd` ← `uds2sovd` dependency ordering is clean |
| Trait seam (`SovdGateway`) | **Good** | Clean injection point; `MockSovdGateway` available |
| Error type hierarchy | **Good** | `UdsError`, `SovdError`, `ProxyError` are typed and carry context |
| Async discipline | **Good** | No blocking calls on async executor; Tokio primitives used throughout |
| Panic discipline | **Good** | No `.unwrap()`/`.expect()` outside `#[cfg(test)]` confirmed |
| Lock ordering | **Good** | Single `RwLock<CdaEcuManager>` shared via `Arc`; no nested lock acquisition |
| Logging | **Good** | `tracing` used throughout; no `println!` in library crates |

### Gaps vs. "Best Quality Standard" for a Production Rust Project

The project meets the standard for an **open-source prototype / research vehicle** but
falls short of production automotive-grade software on these dimensions:

1. **No MC/DC coverage measurement** — ISO 26262 ASIL-B and above require structured
   coverage analysis. `cargo-tarpaulin` is not in the CI matrix.
2. **No Miri / cargo-careful gate** — UB and stacked-borrows violations are not caught.
3. **No fuzzing harness** — protocol deserialization paths (`DoIpMessage::try_from`,
   `RoutingActivationRequest::try_from`) are prime fuzzing targets.
4. **No SBOM generation** — required for automotive supply-chain compliance (ISO/SAE 21434).
5. **No integration test with a real SOVD endpoint** — the CI matrix tests only with
   `MockSovdGateway`. No system-level test verifies that a RDBI request produces correct
   UDS bytes end-to-end with CDA.

---

## Recommended Remediation Order

```
Sprint 1 (safety / correctness):
  F-01  Fix routing activation response length              (1h)
  F-02  Fail on config-load error; remove test_secret       (2h)
  F-03  Add token expiry + re-auth on 401                  (4h)
  F-06  Fix EcuName doc comment formatting                  (15min)
  F-05  Delete orphaned proxy-main/                         (15min)

Sprint 2 (testability / reliability):
  F-07  Introduce EcuManagerProvider trait for unit tests   (1–2 days)
  F-09  Handle DataResponse.errors[]                        (2h)
  F-13  Add TesterPresent pass-through                      (3h)
  F-12  Validate log-level string at config load            (1h)

Sprint 3 (hardening / performance):
  F-04  Warn/error on HTTP gateway URL                      (1h)
  F-10  Replace O(n²) dedup with HashSet                    (30min)
  F-11  Migrate get_token to watch-channel pattern          (3h)
  F-14  Add source-address allowlist to routing handler     (3h)

Sprint 4 (polish):
  F-08  Narrow tokio features in library crates             (30min)
  F-15  Add missing doc comments                            (1h)
  F-16  Remove dead anyhow workspace dep                    (10min)
  F-17  Replace shift/cast with to_be_bytes()               (30min)
  F-18  Remove dead reserved field + TODO                   (15min)
  F-19  Update CODESTYLE.md module map                      (15min)
  F-20  Add UdsSid round-trip test                          (30min)
```

---

*Review completed 2026-05-06. All findings were independently verified against the live
source files. Build state at time of review: `cargo test --locked` → 182 tests pass;
`cargo clippy -D warnings -W clippy::pedantic` → zero warnings.*
