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

## Overview

UDS-to-SOVD Proxy
 
## Overview
 
UDS-to-SOVD Proxy is a Rust-based Adaptor for Diagnostics over Internet Protocol (DoIP) for the Eclipse OpenSOVD ecosystem which helps in translating DoIP requests from an UDS Tester to SoVD requests.
 
It acts as a bridge between DoIP/UDS diagnostic testers and SOVD server. Thus, making the legacy UDS tester work with a SOVD server a possibility.
 
This is acheived by Organizing it into 2 independent parts: 
1. UDS/DoIP Server - frontend interface for the UDS tester.
2. SoVD Proxy - backend which creates, sends HTTP responses to SOVD server & handles responses.
 
## Conceptual Architecture

Though we have 2 parts to UDS-2-SoVD Proxy, for now we are currently working on the **UDS/DoIP Server** part. DoIP Server is created as a library which is used by the standalone uds2sovd-proxy application.

It consists of below components:
1. **Configuration** - helps retrieving configuration from JSOM or TOML file. Also provides a default configuration for testing.
2. **Transport handling** - UDP for discovery & TCP for diagnostic sessions.
3. **Protocol processing** - DoIP protocol specific processing by dispatching requests to the handlers.
4. **Stubbed SoVD proxy** - a pseudo proxy which always responds with `InvalidResponse` error.

![DoIP Server Module Structure](docs/doip_server_architecture_module_structure.svg)

At a high level, testers use UDP for discovery and TCP for diagnostic sessions. Incoming DoIP messages are parsed and dispatched to protocol handlers. Diagnostic payloads are then forwarded to SoVD Proxy.

## Getting Started

```sh
cargo build

cargo run -p doip-server
```

To run doip-server with custom configuration refer to [USAGE.md](docs/doip_server_usage.md).

## Documentation

### Code Documentation (Rustdoc)

The core library documentation is the primary API reference.

```sh
# View the library documentation (main entry point)
cargo doc-lib

# Or without dependencies documentation:
cargo doc --package doipserver-lib --no-deps --open
```

This includes:
- API reference for all core modules
- Quick start examples
- Backend implementation guide

**Additional Resources:**

```sh
# View the server binary documentation
cargo doc --package doip-server --no-deps --open

# View the example client
cargo doc --package doip-example --no-deps --open

# View all workspace crates at once
cargo doc-all
```

### Further Reading

| Document | Description |
| --- | --- |
| [High level architecture](docs/doip_server_high_level_design_detail.md) | Component architecture diagram |
| [Usage](docs/doip_server_usage.md) | Usage guide |
| [Limitation](docs/doip_server_limitation.md) | Limitation of the current design |
| [TODO](docs/doip_server_todo.md) | Improvements and missing features |
