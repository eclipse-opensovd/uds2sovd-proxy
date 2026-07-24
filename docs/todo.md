<!--
SPDX-License-Identifier: Apache-2.0
SPDX-FileCopyrightText: 2026 The Contributors to Eclipse OpenSOVD (see CONTRIBUTORS)

See the NOTICE file(s) distributed with this work for additional
information regarding copyright ownership.

This program and the accompanying materials are made available under the
terms of the Apache License Version 2.0 which is available at
https://www.apache.org/licenses/LICENSE-2.0
-->

This document tracks planned implementation work and longer-term improvements. This list is not exhaustive and is subject to change as the project evolves.

# TODOs

Near-term items that are directly actionable in the current codebase.

## Replace `StubProxy` with real backend integration

**Why**
- Diagnostic forwarding currently ends at `StubProxy`.
- Real UDS-to-SOVD execution path is not available.

**Actions**
- Implement production `SovdProxy` integration.
- Add backend configuration and connection handling.
- Validate end-to-end diagnostic flows.

## Improve shutdown control model

**Why**
- Shutdown is currently triggered by `Ctrl+C`.
- Signal handling should be extensible.

**Actions**
- Support additional termination signals.
- Add programmatic shutdown trigger.
- Add graceful drain behaviour before full stop.

## Add CLI argument parsing

**Why**
- Current startup argument handling can be improved for usability.

**Actions**
- Introduce argument parser (`clap` or equivalent).
- Improve argument validation and error messages.
- Standardize help output and startup options.

## Add future configuration sources

**Why**
- Current providers cover defaults and TOML.
- Future deployments may require alternative sources.

**Actions**
- Add environment-variable provider.
- Evaluate remote configuration service integration.
- Keep the `ConfigProvider` abstraction unchanged.

## Code quality improvement candidates

**Why**
- Repeated constructor-style patterns may appear as the codebase grows.

**Actions**
- Consider `#[derive(new)]` where it improves consistency.
- Apply only when it reduces boilerplate without harming readability.

## Routing activation state machine

**Why**
- Routing activation is currently handled by a simple success response handler.
- A protocol-aware state machine is still missing.

**Actions**
- Model routing activation states and transitions.
- Validate activation requests against the current session context.
- Return protocol-correct activation responses and failures.

# Future work

Longer-term enhancements that depend on architectural evolution, broader interoperability goals, or future deployment requirements.

## Asynchronous backend processing

**Why**
- `SovdProxy::process()` is synchronous.
- Future backend I/O can block and reduce throughput.

**Actions**
- Introduce async backend contract.
- Update diagnostic handling path to async flow.
- Add integration tests for latency and backpressure.

## UDS Response Pending support (`0x78`)

**Why**
- Current flow assumes immediate request/response.
- Long-running diagnostics need response-pending behaviour.

**Actions**
- Add response-pending handling in diagnostic path.
- Validate client interoperability for delayed completion.

## TLS-secured DoIP transport

**Why**
- Current transport is not encrypted.

**Actions**
- Define TLS architecture.
- Add certificate and key management.
- Validate secure client interoperability.

## Additional DoIP message support

**Actions**
- Expand handler coverage for required ISO 13400-2 flows.
- Add protocol compatibility tests.

## Configuration validation hardening

**Actions**
- Strengthen startup validation and error reporting.
- Add invalid-configuration test coverage.
