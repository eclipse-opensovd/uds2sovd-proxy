// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 The Contributors to Eclipse OpenSOVD (see CONTRIBUTORS)
//
// See the NOTICE file(s) distributed with this work for additional
// information regarding copyright ownership.
//
// This program and the accompanying materials are made available under the
// terms of the Apache License Version 2.0 which is available at
// https://www.apache.org/licenses/LICENSE-2.0

//! Configuration data model.
//!
//! Defines the TCP, UDP, and ECU settings consumed by the server at startup.
use serde::Deserialize;
use std::net::SocketAddr;

use super::defaults;
use crate::doip::types::{Eid, Gid, LogicalAddress, Vin};

/// Complete runtime configuration for the server.
///
/// The configuration is split into TCP, UDP, and ECU sections.
/// `#[serde(default)]` allows omitted sections/fields to fall back to
/// compile-time defaults.

#[derive(Debug, Clone, Deserialize, Default)]
#[serde(default)]
pub struct ServerConfig {
    tcp: TcpConfig,
    udp: UdpConfig,
    ecu: EcuConfig,
}

impl ServerConfig {
    /// Consumes this config and returns `(tcp, udp, ecu)` in that order.
    pub fn into_parts(self) -> (TcpConfig, UdpConfig, EcuConfig) {
        (self.tcp, self.udp, self.ecu)
    }
}

/// TCP transport settings.

#[derive(Debug, Clone, Deserialize)]
#[serde(default)]
pub struct TcpConfig {
    address: SocketAddr,
    max_connections: usize,
    logical_address: LogicalAddress,
    read_buffer_size: usize,
}

impl TcpConfig {
    /// Returns the TCP listen address.
    pub fn address(&self) -> SocketAddr {
        self.address
    }

    /// Returns the maximum number of concurrent TCP sessions.
    pub fn max_connections(&self) -> usize {
        self.max_connections
    }

    /// Returns the DoIP logical address used on the TCP path.
    pub fn logical_address(&self) -> LogicalAddress {
        self.logical_address
    }

    /// Returns the TCP read buffer size in bytes.
    pub fn read_buffer_size(&self) -> usize {
        self.read_buffer_size
    }
}

/// UDP transport settings.
#[derive(Debug, Clone, Deserialize)]
#[serde(default)]
pub struct UdpConfig {
    address: SocketAddr,
    logical_address: LogicalAddress,
}

impl UdpConfig {
    /// Returns the UDP listen address.
    pub fn address(&self) -> SocketAddr {
        self.address
    }

    /// Returns the DoIP logical address used on the UDP path.
    pub fn logical_address(&self) -> LogicalAddress {
        self.logical_address
    }
}

impl Default for TcpConfig {
    fn default() -> Self {
        Self {
            address: defaults::TCP_ADDRESS,
            max_connections: defaults::MAX_CONNECTIONS,
            logical_address: defaults::LOGICAL_ADDRESS,
            read_buffer_size: defaults::READ_BUFFER_SIZE,
        }
    }
}

impl Default for UdpConfig {
    fn default() -> Self {
        Self {
            address: defaults::UDP_ADDRESS,
            logical_address: defaults::LOGICAL_ADDRESS,
        }
    }
}

/// ECU identity values advertised in DoIP responses.
#[derive(Debug, Clone, Deserialize)]
pub struct EcuConfig {
    vin: Vin,
    eid: Eid,
    gid: Gid,
}

impl EcuConfig {
    /// Creates ECU identity settings from VIN, EID, and GID values.
    pub fn new(vin: Vin, eid: Eid, gid: Gid) -> Self {
        Self { vin, eid, gid }
    }

    /// Returns the configured VIN.
    pub fn vin(&self) -> Vin {
        self.vin
    }

    /// Returns the configured EID.
    pub fn eid(&self) -> Eid {
        self.eid
    }

    /// Returns the configured GID.
    pub fn gid(&self) -> Gid {
        self.gid
    }
}

impl Default for EcuConfig {
    fn default() -> Self {
        Self {
            vin: defaults::VIN,
            eid: defaults::EID,
            gid: defaults::GID,
        }
    }
}
