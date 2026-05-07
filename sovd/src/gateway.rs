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

//! [`SovdGateway`] — the injectable seam between [`super::mapper::SovdMapper`]
//! and any backend that can serve SOVD data responses.
//!
//! # Why a trait?
//!
//! `SovdMapper` must not branch on a runtime flag to decide whether to make
//! HTTP calls or generate synthetic data.  Instead, the *caller* (normally
//! `uds2sovd::main`) selects an implementation once at startup and injects
//! it as `Arc<dyn SovdGateway>`.  `SovdMapper` never knows which variant it
//! holds.
//!
//! # Implementations shipped in this crate
//!
//! | Type | Behaviour |
//! |---|---|
//! | [`super::client::SovdClient`] | Real HTTP calls to a SOVD REST endpoint (CDA gateway or standalone SOVD server) |
//! | [`super::mock::MockSovdGateway`] | Generates synthetic [`DataResponse`] from MDD POS-RESPONSE metadata — zero I/O, useful for CI and offline development |
//!
//! # Adding your own
//!
//! Implement `SovdGateway` for any type and pass `Arc::new(your_impl)` to
//! [`super::mapper::SovdMapper::new`]:
//!
//! ```rust,no_run
//! use std::sync::Arc;
//! use sovd::gateway::SovdGateway;
//! use sovd::{EcuName, SovdMapper};
//!
//! // struct MyGateway { ... }
//! // #[async_trait::async_trait]
//! // impl SovdGateway for MyGateway { ... }
//! //
//! // let mapper = SovdMapper::new(EcuName::new("ECU"), Arc::new(MyGateway { ... }));
//! ```

use serde_json::{Map, Value};
use uds::error::Result;

use crate::{config::{EcuName, SovdEndpoint}, schema::DataResponse};

/// Implemented by any type that can serve SOVD data responses.
///
/// [`SovdMapper`](super::mapper::SovdMapper) holds an `Arc<dyn SovdGateway>` and
/// calls these two methods without knowing whether the backend makes HTTP calls,
/// generates data from MDD metadata, or returns canned test fixtures.
///
/// # Signature design
///
/// The trait deliberately carries no CDA or MDD types.  All implementation-
/// specific context (e.g. `ServiceResolver`, DID for MUX disambiguation) is
/// bundled inside [`SovdEndpoint`] or stored in the implementation struct at
/// construction time.  This keeps the seam minimal and testable with a trivial stub.
#[async_trait::async_trait]
pub trait SovdGateway: Send + Sync {
    /// Fetch diagnostic data for the given ECU component and SOVD service endpoint.
    ///
    /// # Parameters
    ///
    /// - `component` — typed ECU name used in the SOVD REST URL path.
    /// - `endpoint` — bundles the URL segment, the MDD service name, and the DID.
    ///   HTTP implementations use only `endpoint.as_str()`.
    ///   MDD-based implementations also use `endpoint.service_name()` and `endpoint.did()`.
    ///
    /// # Errors
    ///
    /// Returns an error if the backend cannot produce a response (network error,
    /// metadata missing, HTTP error status, etc.).
    async fn read_data(
        &self,
        component: &EcuName,
        endpoint: &SovdEndpoint,
    ) -> Result<DataResponse>;

    /// Write diagnostic data to the given ECU component and SOVD service endpoint.
    ///
    /// # Parameters
    ///
    /// - `component` — typed ECU name used in the SOVD REST URL path.
    /// - `endpoint` — bundles the URL segment, the MDD service name, and the DID.
    /// - `data` — JSON payload to write.
    ///
    /// # Errors
    ///
    /// Returns an error if the backend rejects the write (network error,
    /// validation failure, HTTP error status, etc.).
    async fn write_data(
        &self,
        component: &EcuName,
        endpoint: &SovdEndpoint,
        data: Map<String, Value>,
    ) -> Result<()>;
}

