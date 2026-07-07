// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 The Contributors to Eclipse OpenSOVD (see CONTRIBUTORS)
//
// See the NOTICE file(s) distributed with this work for additional
// information regarding copyright ownership.
//
// This program and the accompanying materials are made available under the
// terms of the Apache License Version 2.0 which is available at
// https://www.apache.org/licenses/LICENSE-2.0

//! Default configuration values.
//!
//! These constants provide compile-time defaults for transport
//! settings and ECU identity values used when configuration
//! fields are omitted.

use crate::doip::types::{Eid, Gid, LogicalAddress, Vin};
use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4};

/// Default TCP listen address.
///
/// Uses the standard DoIP TCP port (`13400`) and binds to
/// the loopback interface.
pub const TCP_ADDRESS: SocketAddr =
    SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(127, 0, 0, 1), 13400));

/// Default UDP listen address (all interfaces, standard DoIP port 13400).
pub const UDP_ADDRESS: SocketAddr =
    SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(0, 0, 0, 0), 13400));

/// Default maximum number of concurrent TCP sessions.
pub const MAX_CONNECTIONS: usize = 10;

// TODO: Add DEFAULT_MAX_DATA_SIZE constant for entity status response.

/// Default TCP read buffer size in bytes.
pub const READ_BUFFER_SIZE: usize = 4096;

/// Default DoIP logical address advertised by this entity.
///
/// Used in routing activation and diagnostic communication.
pub const LOGICAL_ADDRESS: LogicalAddress = LogicalAddress::new(0x0001);

/// Default Vehicle Identification Number (VIN).
///
/// The default value consists of 17 ASCII zero characters and
/// should be replaced with the actual vehicle VIN in production.
pub const VIN: Vin = Vin::new(*b"00000000000000000");

/// Default Entity Identifier (EID).
///
/// The default value is all zeros and should be replaced with
/// a unique identifier, typically derived from the MAC address
/// of the DoIP network interface.
pub const EID: Eid = Eid::new([0u8; 6]);

/// Default Group Identifier (GID).
///
/// The default value is all zeros.
pub const GID: Gid = Gid::new([0u8; 6]);
