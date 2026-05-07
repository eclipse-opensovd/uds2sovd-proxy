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

//! SOVD-backed [`DiagHandler`] implementation.
//!
//! [`SovdDiagHandler`] combines MDD service resolution ([`ServiceResolver`])
//! with SOVD gateway communication ([`SovdMapper`]) to process UDS requests.

use std::{collections::HashMap, sync::Arc};

use tracing::info;
use uds::{
    DiagHandler, ReadDid, WriteDid,
    error::{ProxyError, Result, UdsError},
};

use crate::{
    config::EcuName,
    mapper::SovdMapper,
    resolver::{ResolvedService, ServiceResolver, ServiceType},
};

/// SOVD-backed diagnostic handler.
///
/// Combines MDD-based service resolution ([`ServiceResolver`]) with SOVD
/// gateway communication ([`SovdMapper`]) to process UDS diagnostic requests.
///
/// Constructed in `uds2sovd` and injected into the `DoIP` server as
/// `Arc<SovdDiagHandler>`.
pub struct SovdDiagHandler {
    /// Typed ECU component name used for service resolution lookup.
    ecu_name: EcuName,
    /// SOVD gateway mapper for request/response translation.
    mapper: SovdMapper,
    /// Per-ECU service resolvers keyed by ECU name.
    ecu_managers: Arc<HashMap<EcuName, Arc<ServiceResolver>>>,
}

impl SovdDiagHandler {
    /// Create a new SOVD diagnostic handler.
    #[must_use]
    pub fn new(
        ecu_name: EcuName,
        mapper: SovdMapper,
        ecu_managers: Arc<HashMap<EcuName, Arc<ServiceResolver>>>,
    ) -> Self {
        Self {
            ecu_name,
            mapper,
            ecu_managers,
        }
    }

    fn ecu_manager(&self) -> Option<&ServiceResolver> {
        self.ecu_managers.get(&self.ecu_name).map(AsRef::as_ref)
    }
}

#[async_trait::async_trait]
impl DiagHandler for SovdDiagHandler {
    /// Handle a `ReadDataByIdentifier` (SID 0x22) request.
    ///
    /// Resolves the DID against the MDD database and forwards to the SOVD
    /// gateway read path.  Returns a UDS positive or negative response.
    ///
    /// # Errors
    /// Returns an error if no MDD database is loaded, the DID is unknown,
    /// or the SOVD gateway request fails.
    async fn read_did(&self, req: &ReadDid) -> Result<Vec<u8>> {
        let mgr = self
            .ecu_manager()
            .ok_or_else(|| ProxyError::Mdd(format!("No MDD database loaded for ECU '{}'", self.ecu_name)))?;

        let ResolvedService {
            name: service_name,
            params: parsed_data,
        } = mgr
            .resolve(ServiceType::Read, req.did.value(), &req.raw)
            .await
            .ok_or(ProxyError::Uds(UdsError::InvalidDid(req.did.value())))?;

        info!("[MDD] READ service found: '{}'", service_name);

        self.mapper
            .process_read_data_request(req.did, &req.raw, mgr, &service_name, Some(parsed_data))
            .await
    }

    /// Handle a `WriteDataByIdentifier` (SID 0x2E) request.
    ///
    /// Resolves the DID against the MDD database and forwards to the SOVD
    /// gateway write path.  Returns a UDS positive or negative response.
    ///
    /// # Errors
    /// Returns an error if no MDD database is loaded, the DID is unknown,
    /// or the SOVD gateway request fails.
    async fn write_did(&self, req: &WriteDid) -> Result<Vec<u8>> {
        let mgr = self
            .ecu_manager()
            .ok_or_else(|| ProxyError::Mdd(format!("No MDD database loaded for ECU '{}'", self.ecu_name)))?;

        let ResolvedService {
            name: service_name,
            params: parsed_data,
        } = mgr
            .resolve(ServiceType::Write, req.did.value(), &req.raw)
            .await
            .ok_or(ProxyError::Uds(UdsError::InvalidDid(req.did.value())))?;

        info!("[MDD] WRITE service found: '{}'", service_name);

        self.mapper
            .process_write_data_request(req.did, &req.raw, &service_name, parsed_data)
            .await
    }
}

#[cfg(test)]
mod tests {
    use std::{collections::HashMap, sync::Arc};

    use serde_json::Map;
    use uds::{DiagHandler, ReadDid, WriteDid};

    use super::*;
    use crate::{
        config::{EcuName, SovdEndpoint},
        gateway::SovdGateway,
        mapper::SovdMapper,
        schema::DataResponse,
    };

    // ── Stub gateway ──────────────────────────────────────────────────────────

    /// A stub gateway that always returns an error — suitable for tests that
    /// expect the handler to fail before reaching the gateway (e.g. "no MDD
    /// database loaded").
    struct NeverCalledGateway;

    #[async_trait::async_trait]
    impl SovdGateway for NeverCalledGateway {
        async fn read_data(
            &self,
            _component: &EcuName,
            _endpoint: &SovdEndpoint,
        ) -> uds::error::Result<DataResponse> {
            panic!("NeverCalledGateway::read_data must not be called in this test")
        }

        async fn write_data(
            &self,
            _component: &EcuName,
            _endpoint: &SovdEndpoint,
            _data: Map<String, serde_json::Value>,
        ) -> uds::error::Result<()> {
            panic!("NeverCalledGateway::write_data must not be called in this test")
        }
    }

    fn make_handler_with_empty_managers() -> SovdDiagHandler {
        let mapper = SovdMapper::new(EcuName::new("ECU"), Arc::new(NeverCalledGateway));
        SovdDiagHandler::new(EcuName::new("ECU"), mapper, Arc::new(HashMap::new()))
    }
    #[test]
    fn ecu_manager_returns_none_for_empty_managers() {
        let handler = make_handler_with_empty_managers();
        assert!(handler.ecu_manager().is_none());
    }

    #[tokio::test]
    async fn handle_read_did_returns_mdd_error_when_no_managers() {
        let handler = make_handler_with_empty_managers();
        let result = handler
            .read_did(&ReadDid { did: 0xF190.into(), raw: vec![0x22, 0xF1, 0x90] })
            .await;
        assert!(result.is_err());
        let err_str = result.unwrap_err().to_string();
        assert!(
            err_str.contains("MDD") || err_str.contains("No MDD"),
            "Expected MDD error, got: {err_str}",
        );
    }

    #[tokio::test]
    async fn handle_write_did_returns_mdd_error_when_no_managers() {
        let handler = make_handler_with_empty_managers();
        let result = handler
            .write_did(&WriteDid { did: 0xF190.into(), raw: vec![0x2E, 0xF1, 0x90, 0x00] })
            .await;
        assert!(result.is_err());
        let err_str = result.unwrap_err().to_string();
        assert!(
            err_str.contains("MDD") || err_str.contains("No MDD"),
            "Expected MDD error, got: {err_str}",
        );
    }
}
