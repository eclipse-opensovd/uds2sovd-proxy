<!--
SPDX-License-Identifier: Apache-2.0
SPDX-FileCopyrightText: 2026 The Contributors to Eclipse OpenSOVD (see CONTRIBUTORS)

See the NOTICE file(s) distributed with this work for additional
information regarding copyright ownership.

This program and the accompanying materials are made available under the
terms of the Apache License Version 2.0 which is available at
https://www.apache.org/licenses/LICENSE-2.0
-->

# DoIP Server — Usage Guide

This document explains how to build, configure, run, and troubleshoot the DoIP server in this repository.

# Configuration

The server supports two configuration modes:

- Default configuration
- TOML configuration file

## Default Configuration

Run the server without arguments to use the built-in defaults:

```bash
cargo run -p doip-server
```

It uses the default configuration defined in [default.rs](../src/config/defaults.rs).

---

## TOML Configuration

Refer to the sample configuration file at [app/sample-doip-server.toml](../app/sample-doip-server.toml). Specify the path to the configuration file when starting the server:

```bash
cargo run -p doip-server -- app/sample-doip-server.toml
```

You can also run from the `app/` directory:

```bash
cd app
cargo run -- sample-doip-server.toml
```

Both configuration modes provide the same runtime behaviour once the server starts.

