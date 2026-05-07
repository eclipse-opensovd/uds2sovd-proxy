/*
 * SPDX-License-Identifier: Apache-2.0
 * SPDX-FileCopyrightText: 2026 The Contributors to Eclipse OpenSOVD (see CONTRIBUTORS)
 *
 * See the NOTICE file(s) distributed with this work for additional
 * information regarding copyright ownership.
 *
 * This program and the accompanying materials are made available under the
 * terms of the Apache License Version 2.0 which is available at
 * https://www.apache.org/licenses/LICENSE-2.0
 */

//! SOVD gateway integration — ISO 22900-4.
//!
//! This crate bridges UDS diagnostic requests to a SOVD REST gateway.
//! It implements the [`DiagHandler`](uds::DiagHandler) trait from
//! `uds` so it can be injected into the `DoIP` transport without the
//! `DoIP` layer having any compile-time knowledge of HTTP or MDD databases.
//!
//! # Crate layout
//!
//! * [`config`] — [`SovdConfig`] and [`EcuConfig`].
//! * [`client`] — [`SovdClient`]: HTTP client, `OAuth2`, mock mode.
//! * [`mapper`] — [`SovdMapper`]: translates UDS ↔ SOVD REST.
//! * [`diag_handler`] — [`SovdDiagHandler`]: implements `DiagHandler`.
//! * [`schema`] — SOVD REST response types.
//! * [`resolver`] — MDD-backed service resolution (CDA dependency lives here).
//!
//! # Pick-and-choose usage
//!
//! ```rust,no_run
//! use std::sync::Arc;
//! use sovd::{EcuName, SovdClient, SovdMapper, config::SovdConfig};
//! // Create a client + mapper without a DoIP server:
//! let client: Arc<dyn sovd::SovdGateway> =
//!     Arc::new(SovdClient::new(SovdConfig::default()).unwrap());
//! let mapper = SovdMapper::new(EcuName::new("MY_ECU"), client);
//! // SovdDiagHandler::new(ecu_name, mapper, ecu_managers) → Arc<dyn DiagHandler>
//! ```

// All public types in this crate intentionally carry the `Sovd` prefix for
// clarity at the call site (e.g. `sovd::SovdClient`, `sovd::SovdMapper`).
// The pedantic lint would fire because the prefix repeats the module name.
#![allow(clippy::module_name_repetitions)]

pub mod client;
pub mod config;
pub mod diag_handler;
pub mod gateway;
pub mod mapper;
pub mod mock;
pub mod resolver;
pub mod schema;

pub use client::SovdClient;
pub use config::{ApiVersion, EcuConfig, EcuName, GatewayUrl, SovdConfig, SovdEndpoint};
pub use diag_handler::SovdDiagHandler;
pub use gateway::SovdGateway;
pub use mapper::SovdMapper;
pub use mock::MockSovdGateway;
pub use resolver::{ResolvedService, ServiceResolver, ServiceType};
