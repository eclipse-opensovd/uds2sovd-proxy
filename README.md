<!--
SPDX-License-Identifier: Apache-2.0
SPDX-FileCopyrightText: 2026 The Contributors to Eclipse OpenSOVD (see CONTRIBUTORS)

See the NOTICE file(s) distributed with this work for additional
information regarding copyright ownership.

This program and the accompanying materials are made available under the
terms of the Apache License Version 2.0 which is available at
https://www.apache.org/licenses/LICENSE-2.0
-->

# UDS-to-SOVD Proxy

This repository contains the UDS-to-SOVD Proxy of the [Eclipse OpenSOVD](https://projects.eclipse.org/projects/automotive.opensovd) project.

The proxy is a protocol translation gateway between legacy UDS (ISO 14229) diagnostic tools and a modern SOVD (ISO 22900-4) vehicle diagnostic architecture. It accepts UDS requests carried over DoIP (ISO 13400-2), resolves the corresponding SOVD service using the ECU's MDD description file, and translates the request into a SOVD REST API call. The SOVD response is then MDD-encoded back into UDS bytes and returned to the requesting tool.

This enables existing UDS-based tools and workflows to interact with SOVD-enabled vehicle architectures without modification.

## Goals

- Transparent UDS ↔ SOVD protocol translation
- Asynchronous I/O — non-blocking throughout
- Minimal footprint — no heap-heavy frameworks
- Layered crate design — each protocol layer is independently testable

## Prerequisites

| Requirement | Version | Notes |
|---|---|---|
| Rust stable toolchain | **1.88.0** | Pinned in `rust-toolchain.toml`; `rustup` installs it automatically |
| Nightly rustfmt | `nightly-2025-07-14` | Required for `cargo fmt` only — `rustup toolchain install nightly-2025-07-14 --component rustfmt` |
| An MDD file | — | ECU diagnostic description in CDA `.mdd` format; a sample is in `examples/mdd/` |

Optional (for pre-commit hooks):

```shell
pip install pre-commit
pre-commit install
```

## Building

```shell
cargo build --release --locked
```

The compiled binary is `target/release/uds2sovdproxy`.

## Running

### Quick start with the built-in mock gateway

The mock gateway returns synthetic MDD-driven responses without a real SOVD server.
It is suitable for integration testing and tool verification.

1. Edit `examples/config.toml` if needed (defaults work out of the box).
2. Run:

```shell
cargo run --release --locked -- \
  --config examples/config.toml \
  --mdd-file examples/mdd/FLXCNG1000.mdd
```

The proxy listens on `0.0.0.0:13400` (DoIP) by default. Connect any UDS-over-DoIP client
(e.g. ETAS INCA, Vector CANoe, a custom DoIP tester) to that port.

### Running against a real SOVD gateway

Set `mock_gateway = false` and point `gateway_url` at your CDA or SOVD server instance:

```toml
# examples/config.toml
[sovd]
mock_gateway = false
gateway_url  = "https://your-cda-host:20002"
client_id    = "your_client_id"
client_secret = "your_client_secret"
```

Then run as above.

### CLI reference

```
uds2sovdproxy --config <FILE> --mdd-file <FILE> [--log-level <LEVEL>]

Options:
  -c, --config     <FILE>   Path to TOML configuration file (required)
  -m, --mdd-file   <FILE>   Path to ECU MDD description file (required)
  -l, --log-level  <LEVEL>  Override log level: error | warn | info | debug | trace
  -h, --help                Print help
```

## Configuration reference

All settings are in a single TOML file. A fully annotated example is at
[`examples/config.toml`](examples/config.toml).

```toml
[server]
doip_port      = 13_400        # DoIP TCP listen port
bind_address   = "0.0.0.0"    # Listen address
max_connections = 10           # Maximum concurrent DoIP sessions
source_address = 3_712         # DoIP entity logical address (0x0E80)

[sovd]
gateway_url   = "http://localhost:20002"  # SOVD gateway base URL
client_id     = "uds2sovd_proxy"
client_secret = "test_secret"            # Replace for production
timeout_ms    = 5_000
mock_gateway  = true           # true = offline mock; false = real SOVD gateway
include_schema = false         # Request JSON schema from SOVD (for debugging)
api_version   = "v15"

[ecu]
default_name    = "AUTO_DETECT"  # ECU name for MDD lookup (auto-detected from MDD)
logical_address = 1              # ECU DoIP logical address
eid = [0, 1, 2, 3, 4, 5]        # DoIP entity identification (6 bytes)
gid = [0, 1, 2, 3, 4, 5]        # DoIP group identification (6 bytes)

[logging]
level  = "info"    # error | warn | info | debug | trace
format = "pretty"  # pretty | json | compact
```

## Architecture

```
DoIP Client (TCP :13400)
     │
     │  DoIP frame (routing activation / diagnostic request)
     ▼
ConnectionHandler          doip/src/handler/
     │  validates framing, checks routing activation state
     ▼
UdsDispatcher              doip/src/uds_dispatcher.rs
     │  parses SID → UdsSid, extracts DID → DataIdentifier
     │  constructs typed request: ReadDid | WriteDid
     ▼
SovdDiagHandler            sovd/src/diag_handler.rs
     │  ServiceResolver::resolve() → SOVD endpoint + params
     │  SovdMapper::process_*_request()
     ▼
SovdGateway (trait)        sovd/src/gateway.rs
     ├─ SovdClient         HTTP GET / PATCH to SOVD REST API
     └─ MockSovdGateway    MDD-driven synthetic response (no HTTP)
     │
     ▼
SovdMapper                 sovd/src/mapper.rs
     │  SOVD JSON → UDS response bytes (via MDD parameter metadata)
     ▼
DoIP Client — UDS response (0x62 / 0x6E)
```

For a full description of each layer and its design decisions see
[ARCHITECTURE.md](ARCHITECTURE.md).

## Workspace layout

```
uds/          ISO 14229 primitives: DiagHandler trait, typed requests,
              UdsSid, DataIdentifier, Nrc, error types
doip/         ISO 13400-2 DoIP transport: TCP server, connection handler,
              UDS dispatcher
sovd/         ISO 22900-4 SOVD integration: MDD resolver (CDA),
              SOVD REST client, SovdDiagHandler
uds2sovd/     Binary: CLI, TOML config, component wiring
examples/
  config.toml         Sample configuration (mock gateway, port 13400)
  mdd/FLXCNG1000.mdd  Sample MDD file for reference and testing
```

## Developing

### Code style

See [CODESTYLE.md](CODESTYLE.md). Key points: Rust 2024 edition, `tracing` for
logging, `thiserror` in library crates, `anyhow` in binaries, pedantic Clippy with
zero warnings.

### Pre-commit hooks

```shell
pre-commit install          # once per clone
pre-commit run --all-files  # run manually
```

### Common commands

| Task | Command |
|---|---|
| Build | `cargo build --locked` |
| Test | `cargo test --locked` |
| Pedantic Clippy | `cargo clippy --all-targets --all-features -- -D warnings -W clippy::pedantic` |
| Format (check) | `cargo +nightly-2025-07-14 fmt -- --check --config error_on_unformatted=true,error_on_line_overflow=true,format_strings=true,group_imports=StdExternalCrate,imports_granularity=Crate` |
| Format (fix) | `cargo +nightly-2025-07-14 fmt -- --config error_on_unformatted=true,error_on_line_overflow=true,format_strings=true,group_imports=StdExternalCrate,imports_granularity=Crate` |
| Dependency audit | `cargo deny check` |

### Testing

Unit tests live in `#[cfg(test)] mod tests` blocks in the same file as the code they test.
Integration tests live under `tests/` in each crate.

```shell
# All tests
cargo test --locked

# Single crate
cargo test --locked -p uds
cargo test --locked -p doip
cargo test --locked -p sovd

# With output
cargo test --locked -- --show-output
```

### Integration tests

End-to-end tests require a running SOVD gateway (or use `mock_gateway = true`).
They are not yet part of the automated CI matrix — tracked in [TODO.md](TODO.md).

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) for the full contributor guide, including
the Eclipse DCO sign-off requirement (`git commit -s`), branch naming conventions,
and the PR checklist.

## License

Apache-2.0 — see [LICENSE](LICENSE).

