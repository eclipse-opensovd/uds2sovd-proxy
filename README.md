<!--
SPDX-License-Identifier: Apache-2.0
SPDX-FileCopyrightText: 2026 The Contributors to Eclipse OpenSOVD (see CONTRIBUTORS)

See the NOTICE file(s) distributed with this work for additional
information regarding copyright ownership.

This program and the accompanying materials are made available under the
terms of the Apache License Version 2.0 which is available at
https://www.apache.org/licenses/LICENSE-2.0
-->

# 🔌 UDS-to-SOVD Proxy 🚗

This repository contains the UDS-to-SOVD Proxy of the Eclipse OpenSOVD project and its documentation.

In the SOVD (Service-Oriented Vehicle Diagnostics) context, the UDS-to-SOVD Proxy serves as a
protocol translation gateway between legacy UDS (Unified Diagnostic Services) based diagnostic
tools and the modern SOVD-based diagnostic architecture.

It accepts UDS requests over DoIP (Diagnostics over IP), resolves the corresponding SOVD service
using the diagnostic description (MDD) of the ECU, and translates them into SOVD REST API calls.
The SOVD responses are then encoded back into UDS format and returned to the requesting tool.

This enables existing UDS-based diagnostic tools and workflows to seamlessly interact with
SOVD-enabled vehicle architectures without modification.

## goals

- 🔄 transparent UDS ↔ SOVD protocol translation
- 🚀 high performance (asynchronous I/O)
- 🤏 low memory and disk-space consumption
- 🛡️ safe & secure
- ⚡ fast startup

## introduction

### usage

### prerequisites


### build the executable


## developing

### pre commit
```shell
uv run https://raw.githubusercontent.com/eclipse-opensovd/cicd-workflows/main/run_checks.py
```
### codestyle

see [codestyle](CODESTYLE.md)

### testing

#### unit tests

Unittests are placed in the relevant module as usual in rust:
```rust
...
#[cfg(test)]
mod test {
    ...
}
```

Run unit tests with:
```shell
cargo test --locked --lib
```

#### integration tests
