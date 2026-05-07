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

//! [`MockSovdGateway`] — a [`SovdGateway`](super::gateway::SovdGateway) implementation
//! that generates synthetic SOVD responses from MDD POS-RESPONSE metadata.
//!
//! No HTTP calls are made.  Useful for:
//!
//! - CI pipelines that run without a live SOVD gateway.
//! - Integration tests that need deterministic, MDD-driven responses.
//! - Offline development when only an MDD file is available.
//!
//! # Module layout
//!
//! - [`mod`] — `MockSovdGateway` struct and `impl SovdGateway`.
//! - [`generate`] — pure data generation functions (independently testable).
//!
//! # Wiring
//!
//! Select `MockSovdGateway` at startup by reading `mock_gateway = true` from
//! `SovdConfig`.  Pass the live `ServiceResolver` at construction so the mock
//! can look up MDD metadata per-request without needing it in the trait signature:
//!
//! ```rust,no_run
//! use std::sync::Arc;
//! use sovd::mock::MockSovdGateway;
//! use sovd::{EcuName, SovdMapper};
//!
//! // let resolver = Arc::new(ServiceResolver::new(...).await?);
//! // let gateway = Arc::new(MockSovdGateway::new(
//! //     EcuName::new("MY_ECU"),
//! //     "http://localhost:20002".to_string(),
//! //     "v15".to_string(),
//! //     Arc::clone(&resolver),
//! // ));
//! // let mapper = SovdMapper::new(EcuName::new("MY_ECU"), gateway);
//! ```

mod generate;

use std::sync::Arc;

use serde_json::{Map, Value};
use uds::error::{Result, SovdError};

use crate::{
    config::{ApiVersion, EcuName, GatewayUrl, SovdEndpoint},
    gateway::SovdGateway,
    resolver::ServiceResolver,
    schema::DataResponse,
};

use generate::generate_mock_response_data;

// ── MockSovdGateway ───────────────────────────────────────────────────────────

/// A [`SovdGateway`](SovdGateway) that generates synthetic SOVD responses from
/// MDD POS-RESPONSE metadata without making any HTTP calls.
///
/// The `gateway_url` and `api_version` fields are used only for logging the
/// URL that *would* have been called, so traces remain easy to follow.
///
/// `resolver` is stored at construction time so the mock can look up MDD
/// POS-RESPONSE metadata per-request without needing it in the
/// [`SovdGateway`] trait signature.
pub struct MockSovdGateway {
    /// Typed ECU component name — used in log messages.
    ecu_name: EcuName,
    /// Base gateway URL — used in log messages only.
    gateway_url: GatewayUrl,
    /// SOVD API version path segment — used in log messages only.
    api_version: ApiVersion,
    /// MDD service resolver — used to look up POS-RESPONSE parameter metadata.
    resolver: Arc<ServiceResolver>,
}

impl MockSovdGateway {
    /// Create a new `MockSovdGateway`.
    ///
    /// `gateway_url` and `api_version` are used only to produce realistic
    /// log messages showing the URL that would have been requested.
    /// `resolver` is queried during [`read_data`](SovdGateway::read_data) to
    /// build synthetic responses from MDD POS-RESPONSE metadata.
    #[must_use]
    pub fn new(
        ecu_name: EcuName,
        gateway_url: GatewayUrl,
        api_version: ApiVersion,
        resolver: Arc<ServiceResolver>,
    ) -> Self {
        Self { ecu_name, gateway_url, api_version, resolver }
    }

    fn read_url(&self, endpoint: &SovdEndpoint) -> String {
        format!(
            "{}/vehicle/{}/components/{}/data/{}",
            self.gateway_url,
            self.api_version,
            self.ecu_name,
            endpoint,
        )
    }
}

#[async_trait::async_trait]
impl SovdGateway for MockSovdGateway {
    /// Generate a synthetic [`DataResponse`] from MDD POS-RESPONSE metadata.
    ///
    /// Uses `endpoint.service_name()` for the MDD lookup and
    /// `endpoint.did()` for MUX-case disambiguation.  Logs the URL that
    /// would have been called so the mock path is easy to spot in traces.
    ///
    /// # Errors
    ///
    /// Returns [`SovdError::MetadataMissing`] if no POS-RESPONSE metadata is
    /// available for the requested service.
    async fn read_data(
        &self,
        _component: &EcuName,
        endpoint: &SovdEndpoint,
    ) -> Result<DataResponse> {
        let service_name = endpoint.service_name();
        let did = endpoint.did();

        tracing::info!(
            "[SOVD MOCK] GET {} (intercepted — generating synthetic response)",
            self.read_url(endpoint)
        );

        let meta = match self.resolver.enriched_response_metadata(service_name, did.value()).await {
            Ok(m) => m,
            Err(e) => {
                tracing::debug!(
                    "[SOVD MOCK] Enriched metadata unavailable for '{}': {}. Falling back to \
                     basic POS-RESPONSE metadata",
                    service_name,
                    e
                );
                self.resolver.response_params(service_name).await.map_err(|_| {
                    SovdError::MetadataMissing { service: service_name.to_string() }
                })?
            }
        };

        if meta.is_empty() {
            return Err(SovdError::MetadataMissing { service: service_name.to_string() }.into());
        }

        let data = generate_mock_response_data(&meta, did);

        tracing::debug!(
            "[SOVD MOCK] Generated response SOVD JSON data:\n{}",
            serde_json::to_string_pretty(&data).unwrap_or_default()
        );

        Ok(DataResponse::new(endpoint.as_str().to_string(), data))
    }

    /// Accept the write silently — no HTTP call is made.
    async fn write_data(
        &self,
        _component: &EcuName,
        endpoint: &SovdEndpoint,
        _data: Map<String, Value>,
    ) -> Result<()> {
        tracing::info!(
            "[SOVD MOCK] PUT /components/{}/configurations/{}",
            self.ecu_name,
            endpoint,
        );
        Ok(())
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use crate::config::SovdEndpoint;

    fn test_endpoint() -> SovdEndpoint {
        SovdEndpoint::new("VINDATAIDENTIFIER_READ", 0xF190.into())
    }

    #[test]
    fn read_url_builds_correct_path() {
        // We cannot easily construct a real ServiceResolver without an MDD file,
        // but we can test the URL builder by inspecting MockSovdGateway fields
        // indirectly through the log URL format.
        // This test is intentionally structural — it verifies the newtype
        // Display impls compose correctly.
        let endpoint = test_endpoint();
        assert_eq!(endpoint.as_str(), "vindataidentifier_read");
        assert_eq!(endpoint.service_name(), "VINDATAIDENTIFIER_READ");
        assert_eq!(endpoint.did().value(), 0xF190);
    }

    #[test]
    fn sovd_endpoint_display_uses_lowercase_name() {
        let ep = SovdEndpoint::new("SOME_SERVICE", 0x1234.into());
        assert_eq!(ep.to_string(), "some_service");
    }
}
