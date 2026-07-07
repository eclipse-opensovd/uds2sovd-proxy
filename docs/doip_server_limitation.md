<!--
SPDX-License-Identifier: Apache-2.0
SPDX-FileCopyrightText: 2026 The Contributors to Eclipse OpenSOVD (see CONTRIBUTORS)

See the NOTICE file(s) distributed with this work for additional
information regarding copyright ownership.

This program and the accompanying materials are made available under the
terms of the Apache License Version 2.0 which is available at
https://www.apache.org/licenses/LICENSE-2.0
-->

# DoIP Server — Current Limitations

This document lists the current functional and operational limitations of this UDS-to-SOVD DoIP server.
It reflects the implementation status in this repository.

---

## 1) Functional Limitations

### 1.1 Stub backend only

**Current state**
- Diagnostic forwarding uses a stub `SovdProxy` implementation.
- A production SOVD backend adapter is not included yet.

**Impact**
- End-to-end transport and protocol flow can be validated.
- Real diagnostic service execution is not available.

**Mitigation**
- Implement and register a production `SovdProxy`.

---

## 2) Protocol Limitations

### 2.1 Partial DoIP message coverage

**Currently supported**
- Vehicle identification (general / by VIN / by EID)
- Entity status request
- Routing activation
- Alive check
- Diagnostic message forwarding

**Impact**
- Message types outside this set are not supported.
- Interoperability depends on whether external tools require unsupported messages.

**Mitigation**
- Add new handlers and register them in the dispatcher.

### 2.2 No TLS-secured DoIP

**Current state**
- TLS transport security is not implemented.

**Impact**
- Traffic is unencrypted on the network path.

**Mitigation**
- Deploy only in a trusted network or behind secured infrastructure.

---

### 2.3 No asynchronous diagnostic processing

**Current state**
- Diagnostic forwarding assumes a request/response interaction.
- Response pending handling is not implemented.

**Impact**
- Long-running diagnostic operations cannot be represented correctly.

**Mitigation**
- Introduce asynchronous backend processing and response pending support.

---

## 3) Operational Limitations

### 3.1 No runtime configuration reload

**Current state**
- Configuration is loaded during startup only.

**Impact**
- Any configuration change requires restart.

**Mitigation**
- Apply configuration updates during planned maintenance windows.

### 3.2 No explicit graceful drain on shutdown

**Current state**
- The application does not provide an explicit session-drain phase before termination.

**Impact**
- In-flight requests may be interrupted during process stop.

**Mitigation**
- Use controlled restarts and avoid shutdown during active diagnostics.

---

## 4) Technical Constraints

### 4.1 Synchronous backend interface

**Current state**
- `SovdProxy` uses a synchronous processing contract.

**Impact**
- Backend implementations that rely on remote I/O may block execution.

**Mitigation**
- Introduce an asynchronous backend contract when integrating a production backend.

### 4.2 In-memory runtime state only

**Current state**
- Session/runtime state is held in memory.

**Impact**
- Runtime state is lost after restart.

**Mitigation**
- Acceptable for current design scope; persistence can be added only if future requirements demand it.

---

## 5) Assumptions

This implementation assumes:
- Single DoIP entity per server instance
- Stable network connectivity
- Single process deployment model
- Backend availability once production backend integration is added

---

## Related Documentation

| Document | Purpose |
| --- | --- |
| [README](../README.md) | Project overview and getting started |
| [HIGH LEVEL DESIGN](doip_server_high_level_design_detail.md) | High-level architecture and design overview |
| [TODO](doip_server_todo.md) | Planned enhancements and roadmap |
| [USAGE](doip_server_usage.md) | Installation, configuration, and operation |

---