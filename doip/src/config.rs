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

//! `DoIP` server and connection configuration (ISO 13400-2).
//!
//! [`ServerConfig`] configures the TCP listener (port, bind address,
//! connection limit).  [`DoipConnectionConfig`] is a minimal per-connection
//! view: the two address fields the [`ConnectionHandler`] actually needs.
//! Keeping these separate avoids passing the full top-level config deep into
//! the connection handler, making it trivially constructible in unit tests.

use std::net::{IpAddr, Ipv4Addr};

use serde::{Deserialize, Deserializer, de};

// ── Default values ────────────────────────────────────────────────────────────

/// Well-known ISO 13400-2 `DoIP` port.
const DEFAULT_DOIP_PORT: u16 = 13400;
const DEFAULT_MAX_CONNECTIONS: usize = 10;
/// Default `DoIP` source (tester) logical address.
const DEFAULT_SOURCE_ADDRESS: u16 = 0x0E80;

// ── ServerConfig ──────────────────────────────────────────────────────────────

/// `DoIP` TCP server configuration (ISO 13400-2).
///
/// Governs the TCP listener: which port and address to bind, how many
/// simultaneous connections to permit, and which logical source address to
/// use in `DoIP` response messages.
#[derive(Debug, Clone, Deserialize)]
pub struct ServerConfig {
    /// TCP port for the `DoIP` server (default: 13400).
    #[serde(deserialize_with = "deserialize_nonzero_u16")]
    pub doip_port: u16,
    /// IP address to bind the server socket to.
    #[serde(deserialize_with = "deserialize_ip_addr")]
    pub bind_address: IpAddr,
    /// Maximum number of concurrent `DoIP` connections.
    #[serde(deserialize_with = "deserialize_max_connections")]
    pub max_connections: usize,
    /// `DoIP` source address used in response messages (tester logical address).
    #[serde(deserialize_with = "deserialize_nonzero_u16")]
    pub source_address: u16,
}

impl Default for ServerConfig {
    fn default() -> Self {
        Self {
            doip_port: DEFAULT_DOIP_PORT,
            bind_address: IpAddr::V4(Ipv4Addr::new(0, 0, 0, 0)),
            max_connections: DEFAULT_MAX_CONNECTIONS,
            source_address: DEFAULT_SOURCE_ADDRESS,
        }
    }
}

// ── DoipConnectionConfig ─────────────────────────────────────────────────────

/// Minimal per-connection addressing extracted from [`ServerConfig`] and the
/// ECU configuration.
///
/// Passed to [`ConnectionHandler`](crate::handler::ConnectionHandler) by
/// value, giving the handler only the two address fields it actually needs
/// and keeping it decoupled from the full top-level config.
///
/// # Copy semantics
///
/// `DoipConnectionConfig` is intentionally `Copy` — it carries two `u16`
/// values and should be cheaply passed around without indirection.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DoipConnectionConfig {
    /// ISO 13400-2 logical address of the ECU being proxied.
    pub ecu_logical_address: u16,
    /// `DoIP` source address used in response messages (tester logical address).
    pub source_address: u16,
}

// ── Private deserialisation helpers ──────────────────────────────────────────

fn deserialize_nonzero_u16<'de, D: Deserializer<'de>>(
    deserializer: D,
) -> std::result::Result<u16, D::Error> {
    let v = u16::deserialize(deserializer)?;
    if v == 0 {
        return Err(de::Error::custom("value must not be zero"));
    }
    Ok(v)
}

fn deserialize_ip_addr<'de, D: Deserializer<'de>>(
    deserializer: D,
) -> std::result::Result<IpAddr, D::Error> {
    let s = String::deserialize(deserializer)?;
    s.parse::<IpAddr>()
        .map_err(|_| de::Error::custom(format!("invalid IP address: {s}")))
}

fn deserialize_max_connections<'de, D: Deserializer<'de>>(
    deserializer: D,
) -> std::result::Result<usize, D::Error> {
    let v = usize::deserialize(deserializer)?;
    if v == 0 {
        return Err(de::Error::custom("value must be greater than zero"));
    }
    Ok(v)
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn server_config_default_port_is_13400() {
        assert_eq!(ServerConfig::default().doip_port, 13400);
    }

    #[test]
    fn doip_connection_config_is_copy() {
        let a = DoipConnectionConfig {
            ecu_logical_address: 0x0001,
            source_address: 0x0E80,
        };
        let b = a; // Copy — no move error
        assert_eq!(a, b);
    }

    #[test]
    fn doip_connection_config_equality() {
        let a = DoipConnectionConfig {
            ecu_logical_address: 0x1234,
            source_address: 0xABCD,
        };
        let b = DoipConnectionConfig {
            ecu_logical_address: 0x1234,
            source_address: 0xABCD,
        };
        assert_eq!(a, b);
        let c = DoipConnectionConfig {
            ecu_logical_address: 0x0001,
            source_address: 0xABCD,
        };
        assert_ne!(a, c);
    }
}
