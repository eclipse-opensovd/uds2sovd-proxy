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

//! [`SovdClient`] — HTTP-based [`SovdGateway`](super::gateway::SovdGateway) implementation.
//!
//! Makes real REST calls to any SOVD endpoint (CDA gateway or standalone SOVD
//! server).  No mock logic lives here; see [`super::mock::MockSovdGateway`] for
//! the offline/CI implementation.
//!
//! # Module layout
//!
//! - [`mod`] — `SovdClient` struct, `impl SovdGateway`, URL builders, token cache.
//! - [`auth`] — `OAuth2` wire types (`AuthRequest`, `AuthResponse`).

mod auth;

use std::{sync::Arc, time::Duration};

use reqwest::{Client, StatusCode};
use serde::Serialize;
use serde_json::{Map, Value};
use tokio::sync::Mutex;
use uds::error::{Result, SovdError};

use crate::{
    config::{EcuName, SovdConfig, SovdEndpoint},
    gateway::SovdGateway,
    schema::DataResponse,
};

use auth::{AuthRequest, AuthResponse};

// ── Wire types ────────────────────────────────────────────────────────────────

/// SOVD write request body.
#[derive(Serialize)]
struct WriteDataRequest {
    data: Value,
}

// ── SovdClient ────────────────────────────────────────────────────────────────

/// HTTP client for communicating with a SOVD REST endpoint.
///
/// Implements [`SovdGateway`] by making real HTTP calls.  Supports `OAuth2`
/// token caching so concurrent requests share a single token.
///
/// Point `gateway_url` at any host that speaks the SOVD REST API — a CDA
/// gateway, a standalone SOVD server, or a test double.
pub struct SovdClient {
    /// SOVD gateway connection settings.
    config: SovdConfig,
    /// HTTP client with configured timeouts.
    client: Client,
    /// Cached `OAuth2` access token.
    access_token: Arc<Mutex<Option<String>>>,
}

impl SovdClient {
    /// Create a new `SovdClient` with the given configuration.
    ///
    /// # Errors
    ///
    /// Returns [`SovdError::Transport`] if the underlying `reqwest` client
    /// cannot be built.
    pub fn new(config: SovdConfig) -> Result<Self> {
        let timeout = Duration::from_millis(config.timeout_ms);
        let client = Client::builder()
            .timeout(timeout)
            .build()
            .map_err(|e| SovdError::Transport(e.to_string()))?;

        Ok(Self {
            config,
            client,
            access_token: Arc::new(Mutex::new(None)),
        })
    }

    // ── URL builders ──────────────────────────────────────────────────────────

    /// Build the SOVD REST URL for reading a data item from a component.
    ///
    /// Template: `{base}/vehicle/{version}/components/{component}/data/{endpoint}`
    pub(crate) fn read_url(&self, component: &EcuName, endpoint: &SovdEndpoint) -> String {
        format!(
            "{}/vehicle/{}/components/{}/data/{}",
            self.config.gateway_url,
            self.config.api_version,
            component,
            endpoint,
        )
    }

    /// Build the SOVD REST URL for writing a data item to a component.
    ///
    /// Template: `{base}/vehicle/{version}/components/{component}/configurations/{endpoint}`
    pub(crate) fn write_url(&self, component: &EcuName, endpoint: &SovdEndpoint) -> String {
        format!(
            "{}/vehicle/{}/components/{}/configurations/{}",
            self.config.gateway_url,
            self.config.api_version,
            component,
            endpoint,
        )
    }

    /// Build the SOVD REST URL for authentication.
    ///
    /// Template: `{base}/vehicle/{version}/authorize`
    pub(crate) fn auth_url(&self) -> String {
        format!(
            "{}/vehicle/{}/authorize",
            self.config.gateway_url, self.config.api_version,
        )
    }

    // ── Authentication ────────────────────────────────────────────────────────

    /// Perform an `OAuth2` client-credentials token exchange and cache the token.
    ///
    /// Forces a fresh token fetch even if the cache is populated.  Useful for
    /// explicit re-authentication after an expired-token error.
    ///
    /// # Errors
    ///
    /// Returns [`SovdError::Auth`] if the server rejects the credentials,
    /// or [`SovdError::Transport`] for network / parse failures.
    pub async fn authenticate(&self) -> Result<String> {
        let token = self.fetch_fresh_token().await?;
        *self.access_token.lock().await = Some(token.clone());
        Ok(token)
    }

    /// Make the raw `OAuth2` HTTP token request.  Does not touch the cache.
    ///
    /// # Errors
    ///
    /// Returns [`SovdError::Auth`] if the server rejects the credentials,
    /// or [`SovdError::Transport`] for network / parse failures.
    async fn fetch_fresh_token(&self) -> Result<String> {
        let url = self.auth_url();

        let auth_req = AuthRequest {
            client_id: self.config.client_id.clone(),
            client_secret: self.config.client_secret.clone(),
        };

        let response = self
            .client
            .post(&url)
            .json(&auth_req)
            .send()
            .await
            .map_err(|e| SovdError::Transport(e.to_string()))?;

        if !response.status().is_success() {
            let status = response.status().as_u16();
            let body = response.text().await.unwrap_or_default();
            return Err(SovdError::Auth { status, body }.into());
        }

        let auth_resp: AuthResponse = response
            .json()
            .await
            .map_err(|e| SovdError::Transport(e.to_string()))?;

        Ok(auth_resp.access_token)
    }

    /// Return a cached access token, or fetch a fresh one atomically.
    ///
    /// Holds a [`Mutex`] for the entire check-and-fetch so only one
    /// token request is ever in flight when the cache is empty.  Concurrent
    /// callers wait at the Mutex and pick up the cached result immediately
    /// after the winning caller releases the lock.
    ///
    /// # Errors
    ///
    /// Propagates any error from [`fetch_fresh_token`](Self::fetch_fresh_token).
    async fn get_token(&self) -> Result<String> {
        let mut guard = self.access_token.lock().await;
        if let Some(token) = guard.as_ref() {
            return Ok(token.clone());
        }
        let token = self.fetch_fresh_token().await?;
        *guard = Some(token.clone());
        Ok(token)
    }
}

// ── SovdGateway impl ──────────────────────────────────────────────────────────

#[async_trait::async_trait]
impl SovdGateway for SovdClient {
    /// Fetch diagnostic data via HTTP GET.
    ///
    /// Uses only `endpoint.as_str()` for the URL — the MDD service name and
    /// DID bundled in `endpoint` are not needed for HTTP transport.
    ///
    /// # Errors
    ///
    /// Returns [`SovdError::EndpointNotFound`] for HTTP 404,
    /// [`SovdError::Transport`] for network/parse failures, and
    /// [`SovdError::HttpStatus`] for other non-2xx responses.
    async fn read_data(
        &self,
        component: &EcuName,
        endpoint: &SovdEndpoint,
    ) -> Result<DataResponse> {
        let token = self.get_token().await?;
        let url = self.read_url(component, endpoint);

        tracing::info!("[SOVD] GET {}", url);

        let mut request = self.client.get(&url).bearer_auth(&token);
        if self.config.include_schema {
            request = request.query(&[("include_schema", "true")]);
        }

        let response = request
            .send()
            .await
            .map_err(|e| SovdError::Transport(e.to_string()))?;

        match response.status() {
            StatusCode::OK => {
                tracing::info!("[SOVD] Response: HTTP 200 OK");
                let data: DataResponse = response
                    .json()
                    .await
                    .map_err(|e| SovdError::Transport(e.to_string()))?;
                tracing::debug!("[SOVD] Data: {} = {:?}", data.id, data.data);
                Ok(data)
            }
            StatusCode::NOT_FOUND => {
                Err(SovdError::EndpointNotFound { endpoint: endpoint.as_str().to_string() }.into())
            }
            status => {
                let body = response.text().await.unwrap_or_default();
                Err(SovdError::HttpStatus { status: status.as_u16(), body }.into())
            }
        }
    }

    /// Write diagnostic data via HTTP PUT.
    ///
    /// # Errors
    ///
    /// Returns [`SovdError::SchemaMismatch`] for HTTP 400,
    /// [`SovdError::EndpointNotFound`] for HTTP 404,
    /// [`SovdError::Transport`] for network failures, and
    /// [`SovdError::HttpStatus`] for other non-2xx responses.
    async fn write_data(
        &self,
        component: &EcuName,
        endpoint: &SovdEndpoint,
        data: Map<String, Value>,
    ) -> Result<()> {
        let token = self.get_token().await?;
        let url = self.write_url(component, endpoint);

        tracing::info!("[SOVD] PUT {}", url);

        let write_req = WriteDataRequest { data: Value::Object(data) };

        let response = self
            .client
            .put(&url)
            .bearer_auth(&token)
            .json(&write_req)
            .send()
            .await
            .map_err(|e| SovdError::Transport(e.to_string()))?;

        match response.status() {
            StatusCode::NO_CONTENT | StatusCode::OK | StatusCode::ACCEPTED => {
                tracing::info!("[SOVD] Write successful: HTTP {}", response.status());
                Ok(())
            }
            StatusCode::BAD_REQUEST => {
                let body = response.text().await.unwrap_or_default();
                Err(SovdError::SchemaMismatch {
                    service: endpoint.service_name().to_string(),
                    reason: format!("Invalid request: {body}"),
                }
                .into())
            }
            StatusCode::NOT_FOUND => {
                Err(SovdError::EndpointNotFound { endpoint: endpoint.as_str().to_string() }.into())
            }
            status => {
                let body = response.text().await.unwrap_or_default();
                Err(SovdError::HttpStatus { status: status.as_u16(), body }.into())
            }
        }
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;
    use crate::schema::DataResponse;

    fn test_config() -> SovdConfig {
        SovdConfig::default()
    }

    fn test_client() -> SovdClient {
        SovdClient::new(test_config()).expect("must build")
    }

    fn test_endpoint() -> SovdEndpoint {
        SovdEndpoint::new("VINDATAIDENTIFIER_READ", 0xF190.into())
    }

    fn test_ecu() -> EcuName {
        EcuName::new("MY_ECU")
    }

    #[test]
    fn client_creation_succeeds() {
        assert!(SovdClient::new(test_config()).is_ok());
    }

    // ── URL builders ──────────────────────────────────────────────────────────

    #[test]
    fn read_url_builds_correct_path() {
        let client = test_client();
        assert_eq!(
            client.read_url(&test_ecu(), &test_endpoint()),
            "http://localhost:20002/vehicle/v15/components/MY_ECU/data/vindataidentifier_read",
        );
    }

    #[test]
    fn write_url_builds_correct_path() {
        let client = test_client();
        assert_eq!(
            client.write_url(&test_ecu(), &test_endpoint()),
            "http://localhost:20002/vehicle/v15/components/MY_ECU/configurations/vindataidentifier_read",
        );
    }

    #[test]
    fn auth_url_builds_correct_path() {
        let client = test_client();
        assert_eq!(client.auth_url(), "http://localhost:20002/vehicle/v15/authorize");
    }

    // ── Serialization ─────────────────────────────────────────────────────────

    #[test]
    fn write_data_request_serializes_payload() {
        let req = WriteDataRequest { data: json!({"VIN": "ABC12345678901234"}) };
        let json = serde_json::to_string(&req).expect("must serialize");
        assert!(json.contains("ABC12345678901234"));
    }

    #[test]
    fn data_response_deserializes_id_and_data() {
        let json = r#"{"id":"VIN","data":{"VIN":"ABC12345678901234"}}"#;
        let resp: DataResponse = serde_json::from_str(json).expect("must deserialize");
        assert_eq!(resp.id, "VIN");
        assert_eq!(resp.data.get("VIN").expect("VIN field"), &json!("ABC12345678901234"));
    }
}
