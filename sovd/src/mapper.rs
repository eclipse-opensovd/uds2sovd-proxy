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

//! UDS ↔ SOVD translation layer.
//!
//! [`SovdMapper`] translates `ReadDataByIdentifier` and `WriteDataByIdentifier`
//! requests into SOVD REST calls and encodes JSON responses back into UDS bytes.

use std::sync::Arc;

use serde_json::{Map, Value};
use uds::{DataIdentifier, error::{Result, SovdError}, uds_service_ids as service_ids};

use crate::{
    config::{EcuName, SovdEndpoint},
    gateway::SovdGateway,
    resolver::ServiceResolver,
    schema::DataResponse,
};

/// Minimum total WDBI UDS request length: SID (1) + DID high (1) + DID low (1).
/// A valid write request must contain at least one data byte beyond this header.
const MIN_WDBI_REQUEST_HEADER_LENGTH: usize = 3;

/// Translates UDS diagnostic requests into SOVD REST calls and back.
///
/// Handles both `ReadDataByIdentifier` (RDBI) and `WriteDataByIdentifier` (WDBI)
/// requests by delegating to the injected [`SovdGateway`] and encoding/decoding
/// the JSON ↔ UDS byte mappings via MDD metadata.
///
/// `SovdMapper` has no knowledge of whether the gateway makes HTTP calls or
/// generates synthetic data — it simply calls `gateway.read_data()` /
/// `gateway.write_data()` and processes the [`crate::schema::DataResponse`]
/// it receives.
///
/// # TODO
///
/// - Handle SOVD `errors[]` array in [`crate::schema::DataResponse`] — map
///   field-level errors to UDS negative responses.
/// - Forward parsed request data to the SOVD gateway for write requests that
///   need request-parameter context.
pub struct SovdMapper {
    /// Typed ECU component name used in SOVD REST paths.
    ecu_name: EcuName,
    /// Injected SOVD data backend.
    gateway: Arc<dyn SovdGateway>,
}

impl SovdMapper {
    /// Create a new `SovdMapper`.
    ///
    /// `ecu_name` is the SOVD component path segment for the target ECU.
    /// `gateway` is any [`SovdGateway`] implementation — pass
    /// `Arc::new(SovdClient::new(config)?)` for production or
    /// `Arc::new(MockSovdGateway::new(...))` for offline/CI mode.
    #[must_use]
    pub fn new(ecu_name: EcuName, gateway: Arc<dyn SovdGateway>) -> Self {
        Self { ecu_name, gateway }
    }

    /// # Errors
    /// Returns an error if the SOVD read request or UDS encoding fails.
    pub async fn process_read_data_request(
        &self,
        did: DataIdentifier,
        uds_request: &[u8],
        resolver: &ServiceResolver,
        service_name: &str,
        parsed_data: Option<Map<String, Value>>,
    ) -> Result<Vec<u8>> {
        tracing::debug!(
            "[RDBI] DID {} service='{}' request={:02X?}",
            did,
            service_name,
            uds_request
        );
        if let Some(ref parsed) = parsed_data {
            tracing::trace!(
                "[RDBI] Parsed request: {}",
                serde_json::to_string_pretty(parsed).unwrap_or_default()
            );
        }

        let endpoint = SovdEndpoint::new(service_name, did);

        let sovd_response = self
            .gateway
            .read_data(&self.ecu_name, &endpoint)
            .await?;
        tracing::debug!(
            "[RDBI] SOVD response for '{}': {:?}",
            endpoint,
            sovd_response.data
        );

        let uds_response = self
            .sovd_json_to_uds(did, &sovd_response, resolver, service_name)
            .await?;

        tracing::info!(
            "[RDBI] DID {} '{}' -> {} bytes: {:02X?}",
            did,
            service_name,
            uds_response.len(),
            uds_response
        );
        Ok(uds_response)
    }

    /// # Errors
    /// Returns an error if the SOVD write request fails.
    pub async fn process_write_data_request(
        &self,
        did: DataIdentifier,
        uds_request: &[u8],
        service_name: &str,
        parsed_data: Map<String, Value>,
    ) -> Result<Vec<u8>> {
        if uds_request.len() <= MIN_WDBI_REQUEST_HEADER_LENGTH {
            return Err(SovdError::SchemaMismatch {
                service: service_name.to_string(),
                reason: "Write request missing data bytes".to_string(),
            }
            .into());
        }

        let endpoint = SovdEndpoint::new(service_name, did);

        tracing::debug!(
            "[WDBI] SOVD JSON data: {}",
            serde_json::to_string_pretty(&parsed_data).unwrap_or_default()
        );

        self.gateway
            .write_data(&self.ecu_name, &endpoint, parsed_data)
            .await?;

        let uds_response = vec![
            service_ids::WRITE_DATA_BY_IDENTIFIER | service_ids::POSITIVE_RESPONSE_BITMASK,
            (did.value() >> 8) as u8,
            (did.value() & 0xFF) as u8,
        ];

        tracing::info!(
            "[WDBI] DID {} '{}' -> {} bytes",
            did,
            service_name,
            uds_response.len()
        );
        Ok(uds_response)
    }

    /// Convert a SOVD JSON response into raw UDS response bytes.
    ///
    /// Delegates encoding to [`ResponseEncoder`], which uses MDD POS-RESPONSE
    /// parameter metadata to place each field at its correct byte offset.
    ///
    /// # Errors
    /// Returns an error if the MDD encoder cannot produce a valid response
    /// for the given service name.
    async fn sovd_json_to_uds(
        &self,
        did: DataIdentifier,
        sovd_response: &DataResponse,
        resolver: &ServiceResolver,
        service_name: &str,
    ) -> Result<Vec<u8>> {
        let uds_bytes = resolver
            .build_uds_response(
                service_name,
                service_ids::READ_DATA_BY_IDENTIFIER,
                did.value(),
                sovd_response.data.iter().map(|(k, v)| (k.clone(), v.clone())).collect(),
            )
            .await
            .map_err(|e| {
                SovdError::SchemaMismatch {
                    service: service_name.to_string(),
                    reason: format!("MDD failed to encode response: {e}"),
                }
            })?;

        tracing::debug!(
            "[MDD] SOVD JSON -> UDS for '{}': {:02X?}",
            service_name,
            uds_bytes
        );

        Ok(uds_bytes)
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use serde_json::Map;

    use super::*;
    use crate::{
        config::{EcuName, SovdEndpoint},
        gateway::SovdGateway,
        schema::DataResponse,
    };

    // ── Stub gateway for mapper tests ─────────────────────────────────────────

    /// A minimal gateway stub that returns `Ok(())` for writes and errors for reads.
    struct AlwaysOkWriteGateway;

    #[async_trait::async_trait]
    impl SovdGateway for AlwaysOkWriteGateway {
        async fn read_data(
            &self,
            _component: &EcuName,
            endpoint: &SovdEndpoint,
        ) -> uds::error::Result<DataResponse> {
            Err(uds::error::SovdError::EndpointNotFound {
                endpoint: endpoint.as_str().to_string(),
            }
            .into())
        }

        async fn write_data(
            &self,
            _component: &EcuName,
            _endpoint: &SovdEndpoint,
            _data: Map<String, serde_json::Value>,
        ) -> uds::error::Result<()> {
            Ok(())
        }
    }

    fn make_mapper() -> SovdMapper {
        SovdMapper::new(EcuName::new("ECU"), Arc::new(AlwaysOkWriteGateway))
    }

    #[test]
    fn test_service_to_sovd_endpoint() {
        assert_eq!("READ_IDENTIFIER".to_lowercase(), "read_identifier");
        assert_eq!("WRITE_IDENTIFIER".to_lowercase(), "write_identifier");
    }

    #[test]
    fn mapper_ecu_name_stored_correctly() {
        let mapper = make_mapper();
        assert_eq!(mapper.ecu_name, EcuName::new("ECU"));
    }

    #[tokio::test]
    async fn process_write_request_too_short_returns_schema_mismatch_error() {
        let mapper = make_mapper();
        // Exactly MIN_WDBI_REQUEST_HEADER_LENGTH (3) bytes — triggers the error.
        let short_request: &[u8] = &[0x2E, 0xF1, 0x90];
        let result = mapper
            .process_write_data_request(0xF190.into(), short_request, "SOME_SERVICE", Map::new())
            .await;
        assert!(result.is_err(), "Too-short WDBI request must return an error");
        let err_str = result.unwrap_err().to_string();
        assert!(
            err_str.contains("mismatch") || err_str.contains("missing"),
            "Expected SchemaMismatch error, got: {err_str}",
        );
    }

    #[tokio::test]
    async fn process_write_request_returns_positive_response() {
        let mapper = make_mapper();
        // 4 bytes = SID + DID_HI + DID_LO + 1 data byte — satisfies `> MIN_WDBI_REQUEST_HEADER_LENGTH`.
        let request: &[u8] = &[0x2E, 0xF1, 0x90, 0x01];
        let result = mapper
            .process_write_data_request(0xF190.into(), request, "SomeService", Map::new())
            .await;
        let response = result.expect("stub write must succeed");
        assert_eq!(
            response,
            vec![0x6E, 0xF1, 0x90],
            "WDBI positive response must be [SID|0x40, DID_HI, DID_LO]",
        );
    }
}
