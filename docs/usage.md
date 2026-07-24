<!--
SPDX-License-Identifier: Apache-2.0
SPDX-FileCopyrightText: 2026 The Contributors to Eclipse OpenSOVD (see CONTRIBUTORS)

See the NOTICE file(s) distributed with this work for additional
information regarding copyright ownership.

This program and the accompanying materials are made available under the
terms of the Apache License Version 2.0 which is available at
https://www.apache.org/licenses/LICENSE-2.0
-->

# Usage Guide

This document explains how to build, configure, and run the UDS-to-SOVD Proxy.

## Command Line Arguments

The server accepts the following arguments:

```bash
cargo run -p uds2sovd-proxy [CONFIG_FILE]
```

**Arguments:**
- `CONFIG_FILE` (optional): Path to a TOML configuration file. If not provided, the server uses built-in defaults.

**Examples:**
```bash
# Run with default configuration
cargo run -p uds2sovd-proxy

# Run with custom config file (absolute path)
cargo run -p uds2sovd-proxy -- /etc/doip/config.toml

# Run with relative path
cargo run -p uds2sovd-proxy -- app/config.toml

# Run from app directory
cd app
cargo run -- config.toml
```

## Configuration

The server supports two configuration modes:

- **Default configuration**: Built-in programmatic defaults (no file needed)
- **TOML configuration file**: Custom configuration from a TOML file

## Default Configuration

Run the server without arguments to use the built-in defaults:

```bash
cargo run -p uds2sovd-proxy
```

It uses the default configuration defined in [defaults.rs](../src/config/defaults.rs).

## TOML Configuration

Refer to the sample configuration file at [app/config.toml](../app/config.toml). Specify the path to the configuration file when starting the server:

```bash
cargo run -p uds2sovd-proxy -- app/config.toml
```

You can also run from the `app/` directory:

```bash
cd app
cargo run -- config.toml
```

Both configuration modes provide the same runtime behaviour once the server starts.

## Related Documentation

| Document | Purpose |
| --- | --- |
| [README](../README.md) | Project overview and quick start |
| [Detailed design](detailed_design.md) | Architecture and runtime behaviour |
| [Limitations](limitation.md) | Current functional and operational constraints |
| [TODO](todo.md) | Planned enhancements and roadmap |
