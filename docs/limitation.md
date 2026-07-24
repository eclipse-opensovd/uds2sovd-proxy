<!--
SPDX-License-Identifier: Apache-2.0
SPDX-FileCopyrightText: 2026 The Contributors to Eclipse OpenSOVD (see CONTRIBUTORS)

See the NOTICE file(s) distributed with this work for additional
information regarding copyright ownership.

This program and the accompanying materials are made available under the
terms of the Apache License Version 2.0 which is available at
https://www.apache.org/licenses/LICENSE-2.0
-->

This document lists the current constraints of the UDS-to-SOVD Proxy.
Any known mitigations are documented in the [TODO](todo.md).

# Limitations

## Stub backend only

**Current state**
- Diagnostic forwarding uses a stub `SovdProxy` implementation.
- A production SOVD backend adapter is not included yet.

**Impact**
- End-to-end transport and protocol flow can be validated.
- Real diagnostic service execution is not available.

## Partial DoIP message coverage

**Currently supported**
- Vehicle identification (general / by VIN / by EID)
- Entity status request
- Routing activation
- Alive check
- Diagnostic message forwarding

**Impact**
- Message types outside this set are not supported.
- Interoperability depends on whether external tools require unsupported messages.

## No TLS-secured DoIP

**Current state**
- TLS transport security is not implemented.

**Impact**
- Traffic is unencrypted on the network path.

## No asynchronous diagnostic processing

**Current state**
- Diagnostic forwarding assumes a request/response interaction.
- Response pending handling is not implemented.

**Impact**
- Long-running diagnostic operations cannot be represented correctly.

## No explicit graceful drain on shutdown

**Current state**
- The application does not provide an explicit session-drain phase before termination.

**Impact**
- In-flight requests may be interrupted during process stop.

## Synchronous backend interface

**Current state**
- `SovdProxy` uses a synchronous processing contract.

**Impact**
- Backend implementations that rely on remote I/O may block execution.

# Related Documentation

| Document | Purpose |
| --- | --- |
| [README](../README.md) | Project overview and getting started |
| [Detailed Design](detailed_design.md) | System architecture and design rationale |
| [TODO](todo.md) | Planned enhancements and roadmap |
| [Usage](usage.md) | Installation, configuration, and operation |
