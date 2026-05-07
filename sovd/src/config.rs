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

//! SOVD gateway and ECU configuration.
//!
//! [`SovdConfig`] holds all parameters needed to connect to the SOVD gateway
//! (URL, credentials, timeouts, mock flag).  [`EcuConfig`] holds the ECU
//! identity used for MDD lookups and `DoIP` addressing.

use std::fmt;

use serde::{Deserialize, Deserializer, de};
use uds::DataIdentifier;

// ── Required byte length for EID/GID per ISO 13400-2 ─────────────────────────
const EID_GID_BYTE_LENGTH: usize = 6;

// ── Default values ────────────────────────────────────────────────────────────
const DEFAULT_GATEWAY_URL: &str = "http://localhost:20002";
const DEFAULT_CLIENT_ID: &str = "uds2sovd_proxy";
const DEFAULT_CLIENT_SECRET: &str = "test_secret";
const DEFAULT_TIMEOUT_MS: u64 = 5000;
const DEFAULT_API_VERSION: &str = "v15";
const DEFAULT_ECU_NAME: &str = "ECU";

// ── GatewayUrl ────────────────────────────────────────────────────────────────

/// Base URL of the SOVD gateway (e.g. `http://localhost:20002`).
///
/// Using a newtype prevents accidentally passing an `ApiVersion`, `EcuName`,
/// or any other string where a gateway URL is expected.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(transparent)]
pub struct GatewayUrl(String);

impl GatewayUrl {
    /// Construct a `GatewayUrl` from any string-like value.
    pub fn new(url: impl Into<String>) -> Self {
        Self(url.into())
    }

    /// Borrow the inner string.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for GatewayUrl {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl AsRef<str> for GatewayUrl {
    fn as_ref(&self) -> &str {
        &self.0
    }
}

impl From<String> for GatewayUrl {
    fn from(s: String) -> Self {
        Self(s)
    }
}

// ── ApiVersion ────────────────────────────────────────────────────────────────

/// SOVD API version path segment (e.g. `"v15"`).
///
/// Used as a URL path segment: `/vehicle/{api_version}/components/…`.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(transparent)]
pub struct ApiVersion(String);

impl ApiVersion {
    /// Construct an `ApiVersion` from any string-like value.
    pub fn new(v: impl Into<String>) -> Self {
        Self(v.into())
    }

    /// Borrow the inner string.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for ApiVersion {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl AsRef<str> for ApiVersion {
    fn as_ref(&self) -> &str {
        &self.0
    }
}

impl From<String> for ApiVersion {
    fn from(s: String) -> Self {
        Self(s)
    }
}

// ── SovdEndpoint ──────────────────────────────────────────────────────────────

/// Typed SOVD service endpoint descriptor.
///
/// Bundles the three pieces of information that uniquely identify a SOVD data
/// operation, keeping the [`SovdGateway`](crate::gateway::SovdGateway) trait
/// signature narrow (two arguments instead of five):
///
/// - `name` — lowercase URL path segment, e.g. `"vindataidentifier_read"`.
/// - `service_name` — original MDD service name used for metadata lookup,
///   e.g. `"VINDATAIDENTIFIER_READ"`.
/// - `did` — Data Identifier for MUX-case disambiguation in mock implementations.
///
/// HTTP implementations use only [`as_str`](Self::as_str).
/// MDD-based mock implementations use all three accessors.
#[derive(Debug, Clone)]
pub struct SovdEndpoint {
    /// Lowercase URL path segment.
    name: String,
    /// Original MDD service name (uppercase convention).
    service_name: String,
    /// Data Identifier associated with this endpoint.
    did: DataIdentifier,
}

impl SovdEndpoint {
    /// Construct a `SovdEndpoint` from an MDD service name and the associated DID.
    ///
    /// The lowercase URL segment is derived automatically from `service_name`.
    pub fn new(service_name: impl Into<String>, did: DataIdentifier) -> Self {
        let service_name = service_name.into();
        let name = service_name.to_lowercase();
        Self { name, service_name, did }
    }

    /// URL path segment (lowercase) — use this in REST URL construction.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.name
    }

    /// Original MDD service name — use this for metadata lookups.
    #[must_use]
    pub fn service_name(&self) -> &str {
        &self.service_name
    }

    /// Data Identifier — use this for MUX-case disambiguation.
    #[must_use]
    pub fn did(&self) -> DataIdentifier {
        self.did
    }
}

impl AsRef<str> for SovdEndpoint {
    /// Borrow the URL path segment (lowercase).
    fn as_ref(&self) -> &str {
        &self.name
    }
}

impl fmt::Display for SovdEndpoint {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.name)
    }
}

// ── EcuName ───────────────────────────────────────────────────────────────────

/// Typed ECU identifier used as a SOVD component path segment and MDD lookup
/// key.
///
/// Wrapping the raw `String` prevents accidental confusion with other string
/// values (e.g. service names, endpoint paths, gateway URLs).
#[derive(Debug, Clone, PartialEq, Eq, Hash, Deserialize)]
#[serde(transparent)]
pub struct EcuName(String);

impl EcuName {
    /// Construct an `EcuName` from any string-like value.
    pub fn new(name: impl Into<String>) -> Self {
        Self(name.into())
    }

    /// Borrow the inner string.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for EcuName {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl AsRef<str> for EcuName {
    fn as_ref(&self) -> &str {
        &self.0
    }
}

impl From<String> for EcuName {
    fn from(s: String) -> Self {
        Self(s)
    }
}

impl From<&str> for EcuName {
    fn from(s: &str) -> Self {
        Self(s.to_string())
    }
}

// ── SovdConfig ────────────────────────────────────────────────────────────────

/// SOVD gateway connection configuration (ISO 22900-4).
///
/// Controls how the proxy reaches the SOVD gateway: base URL, `OAuth2`
/// credentials, HTTP timeout, API version path segment, and whether to
/// use mock responses instead of real HTTP calls.
#[derive(Debug, Clone, Deserialize)]
pub struct SovdConfig {
    /// Base URL of the SOVD gateway (e.g. `http://localhost:20002`).
    #[serde(deserialize_with = "deserialize_nonempty_gateway_url")]
    pub gateway_url: GatewayUrl,
    /// `OAuth2` client ID for gateway authentication.
    pub client_id: String,
    /// `OAuth2` client secret for gateway authentication.
    pub client_secret: String,
    /// HTTP request timeout in milliseconds.
    pub timeout_ms: u64,
    /// SOVD API version path segment (e.g. `v15`).
    pub api_version: ApiVersion,
    /// Whether to request inline schema in data responses.
    #[serde(default = "SovdConfig::default_include_schema")]
    pub include_schema: bool,
    /// When `true`, bypass HTTP calls and generate synthetic responses from
    /// MDD metadata.  Useful for integration tests without a live SOVD server.
    #[serde(default)]
    pub mock_gateway: bool,
}

impl SovdConfig {
    fn default_include_schema() -> bool {
        true
    }
}

impl Default for SovdConfig {
    fn default() -> Self {
        Self {
            gateway_url: GatewayUrl::new(DEFAULT_GATEWAY_URL),
            client_id: DEFAULT_CLIENT_ID.to_string(),
            client_secret: DEFAULT_CLIENT_SECRET.to_string(),
            timeout_ms: DEFAULT_TIMEOUT_MS,
            api_version: ApiVersion::new(DEFAULT_API_VERSION),
            include_schema: true,
            mock_gateway: false,
        }
    }
}

// ── EcuConfig ─────────────────────────────────────────────────────────────────

/// ECU identity and addressing configuration.
///
/// Used to identify the ECU in MDD lookups, SOVD component paths,
/// and `DoIP` vehicle-identification responses.
#[derive(Debug, Clone, Deserialize)]
pub struct EcuConfig {
    /// Default ECU name used as the SOVD component path segment.
    pub default_name: EcuName,
    /// ISO 13400-2 logical address of the target ECU.
    #[serde(deserialize_with = "deserialize_nonzero_u16")]
    pub logical_address: u16,
    /// 6-byte Entity Identification (typically a MAC address).
    pub eid: [u8; EID_GID_BYTE_LENGTH],
    /// 6-byte Group Identification.
    pub gid: [u8; EID_GID_BYTE_LENGTH],
}

impl Default for EcuConfig {
    fn default() -> Self {
        Self {
            default_name: EcuName::new(DEFAULT_ECU_NAME),
            logical_address: 0x0001,
            eid: [0x00, 0x01, 0x02, 0x03, 0x04, 0x05],
            gid: [0x00, 0x01, 0x02, 0x03, 0x04, 0x05],
        }
    }
}

// ── Private deserialisation helpers ──────────────────────────────────────────

fn deserialize_nonempty_gateway_url<'de, D: Deserializer<'de>>(
    deserializer: D,
) -> std::result::Result<GatewayUrl, D::Error> {
    let s = String::deserialize(deserializer)?;
    if s.is_empty() {
        return Err(de::Error::custom("gateway_url must not be empty"));
    }
    Ok(GatewayUrl::new(s))
}

fn deserialize_nonzero_u16<'de, D: Deserializer<'de>>(
    deserializer: D,
) -> std::result::Result<u16, D::Error> {
    let v = u16::deserialize(deserializer)?;
    if v == 0 {
        return Err(de::Error::custom("value must not be zero"));
    }
    Ok(v)
}
