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

//! MDD-driven UDS service resolution and UDS response encoding.
//!
//! [`ServiceResolver`] is a facade over the CDA `EcuManager`.  It owns
//! three focused sub-components:
//!
//! - [`MetadataProvider`] — request/response parameter metadata from the MDD.
//! - [`DidResolver`] — DID-to-service-name resolution via prefix lookup.
//! - [`ResponseEncoder`] — encodes SOVD JSON data into UDS response bytes.
//!
//! # Note on CDA coupling
//!
//! This module (and all its sub-modules) depends on `cda-*` crates.  It lives
//! in the `sovd` crate so that neither `doip` nor `uds` pulls in the CDA
//! MDD parser as a transitive dependency.

pub(crate) mod encoding;
pub(crate) mod metadata;
pub(crate) mod mux;
pub(crate) mod params;
pub(crate) mod resolve;
pub(crate) mod response;
pub mod uds_helpers;

use std::sync::Arc;

use cda_core::{DiagServiceResponseStruct, EcuManager as CdaEcuManager};
use cda_database::datatypes::DiagnosticDatabase;
use cda_interfaces::{
    DiagComm, DiagCommType, DiagServiceError, EcuManager as EcuManagerTrait, EcuManagerType,
    FunctionalDescriptionConfig, HashMap, Protocol, ResponseParameterInfo,
    datatypes::{ComParams, DatabaseNamingConvention, DiagnosticServiceAffixPosition},
    diagservices::DiagServiceResponseType,
};
use cda_plugin_security::DefaultSecurityPluginData;
pub use metadata::MetadataProvider;
pub use resolve::{DidResolver, ResolvedService, ServiceType};
pub use response::ResponseEncoder;
use tokio::sync::RwLock;
pub use mux::find_mux_case_prefix;

use crate::config::EcuName;

pub(crate) type ManagerHandle = Arc<RwLock<CdaEcuManager<DefaultSecurityPluginData>>>;

/// Minimum UDS positive response buffer size: response SID (1) + DID high (1) + DID low (1).
pub(crate) const UDS_POSITIVE_RESPONSE_MIN_SIZE: usize = 3;

/// MDD-backed service resolver for a single ECU.
///
/// Wraps the CDA [`EcuManager`](cda_core::EcuManager) and exposes a focused
/// API for DID resolution, metadata retrieval, and UDS response encoding.
pub struct ServiceResolver {
    /// DID-to-service resolution.
    resolver: DidResolver,
    /// UDS response encoding from SOVD JSON data.
    encoder: ResponseEncoder,
    /// MDD metadata queries (request/response parameter info, MUX cases).
    metadata: MetadataProvider,
    ecu_name: EcuName,
}

impl ServiceResolver {
    /// Initialise from an ECU name and a loaded MDD database.
    ///
    /// # Errors
    ///
    /// Returns `DiagServiceError` when the CDA `EcuManager` cannot be created
    /// or the base variant fails to activate.
    pub async fn new(
        ecu_name: EcuName,
        db: DiagnosticDatabase,
        logical_address: u16,
        tester_address: u16,
    ) -> Result<Self, DiagServiceError> {
        let com_params = Self::default_com_params(logical_address, tester_address);

        let func_config = FunctionalDescriptionConfig {
            description_database: String::new(),
            enabled_functional_groups: None,
            protocol_position: DiagnosticServiceAffixPosition::Prefix,
            protocol_case_sensitive: false,
        };

        let mut manager = CdaEcuManager::new(
            db,
            Protocol::DoIp,
            &com_params,
            DatabaseNamingConvention::default(),
            EcuManagerType::Ecu,
            &func_config,
            true,
        )
        .map_err(|e| {
            tracing::error!("Failed to create EcuManager: {}", e);
            e
        })?;

        Self::activate_base_variant(&mut manager).await?;

        let handle: ManagerHandle = Arc::new(RwLock::new(manager));

        let metadata = MetadataProvider::new(Arc::clone(&handle));
        Ok(Self {
            resolver: DidResolver::new(Arc::clone(&handle)),
            encoder: ResponseEncoder::new(metadata.clone()),
            metadata,
            ecu_name,
        })
    }

    /// Get the ECU name this resolver was initialised with.
    #[must_use]
    pub fn ecu_name(&self) -> &str {
        self.ecu_name.as_str()
    }

    /// Resolve the best-matching service for a UDS DID request.
    ///
    /// Returns `None` when no service is registered for the given DID.
    pub async fn resolve(
        &self,
        service_type: ServiceType,
        did: u16,
        uds_bytes: &[u8],
    ) -> Option<ResolvedService> {
        self.resolver.resolve(service_type, did, uds_bytes).await
    }

    /// Retrieve enriched POS-RESPONSE metadata for a service and DID.
    ///
    /// # Errors
    /// Returns `DiagServiceError` when the base metadata lookup fails.
    pub async fn enriched_response_metadata(
        &self,
        service_name: &str,
        did: u16,
    ) -> Result<Vec<ResponseParameterInfo>, DiagServiceError> {
        self.metadata
            .get_enriched_response_metadata(service_name, did)
            .await
    }

    /// Retrieve POS-RESPONSE parameter metadata for a service.
    ///
    /// # Errors
    /// Returns `DiagServiceError` when the service is unknown or has no
    /// response metadata.
    pub async fn response_params(
        &self,
        service_name: &str,
    ) -> Result<Vec<ResponseParameterInfo>, DiagServiceError> {
        self.metadata.get_response_params(service_name).await
    }

    /// Build the UDS response bytes for a SOVD data payload.
    ///
    /// # Errors
    /// Returns `DiagServiceError` when the MDD encoder cannot produce a
    /// valid response for the given service name.
    pub async fn build_uds_response(
        &self,
        service_name: &str,
        sid: u8,
        did: u16,
        response_data: std::collections::HashMap<String, serde_json::Value>,
    ) -> Result<Vec<u8>, DiagServiceError> {
        self.encoder
            .build_response(service_name, sid, did, response_data)
            .await
    }

    fn default_com_params(logical_address: u16, tester_address: u16) -> ComParams {
        let mut com_params = ComParams::default();
        com_params.doip.logical_gateway_address.default = logical_address;
        com_params.doip.logical_ecu_address.default = logical_address;
        com_params.doip.logical_tester_address.default = tester_address;
        com_params
    }

    /// Activate the base (fallback) ECU variant.
    ///
    /// Seeds the CDA diagnostic engine with a synthetic dummy response so
    /// that `detect_variant` initialises its internal state-chart.
    ///
    /// # Errors
    ///
    /// Returns `DiagServiceError` when `detect_variant` fails and no
    /// variant name was set.
    async fn activate_base_variant(
        manager: &mut CdaEcuManager<DefaultSecurityPluginData>,
    ) -> Result<(), DiagServiceError> {
        // TODO(#16): replace with real variant-identification DID reads.
        let dummy_response = DiagServiceResponseStruct {
            service: DiagComm {
                name: String::new(),
                type_: DiagCommType::Data,
                lookup_name: None,
            },
            data: vec![],
            mapped_data: None,
            response_type: DiagServiceResponseType::Positive,
        };

        let mut responses: HashMap<String, DiagServiceResponseStruct> = HashMap::default();
        responses.insert("__variant_init__".to_string(), dummy_response);

        manager
            .detect_variant(responses)
            .await
            .or_else(|e| match manager.variant().name {
                Some(ref name) => {
                    tracing::info!(
                        "Base variant '{}' activated (state chart init skipped: {})",
                        name,
                        e
                    );
                    Ok(())
                }
                None => Err(e),
            })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_com_params() {
        let com_params = ServiceResolver::default_com_params(0x1000, 0x0E80);
        assert_eq!(com_params.doip.logical_gateway_address.default, 0x1000);
        assert_eq!(com_params.doip.logical_ecu_address.default, 0x1000);
        assert_eq!(com_params.doip.logical_tester_address.default, 0x0E80);
        assert_eq!(
            com_params.doip.logical_gateway_address.name,
            "CP_DoIPLogicalGatewayAddress"
        );
        assert_eq!(
            com_params.doip.logical_ecu_address.name,
            "CP_DoIPLogicalEcuAddress"
        );
        assert_eq!(
            com_params.doip.logical_response_id_table_name,
            "CP_UniqueRespIdTable"
        );
    }
}
