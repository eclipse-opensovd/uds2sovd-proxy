// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 The Contributors to Eclipse OpenSOVD (see CONTRIBUTORS)
//
// See the NOTICE file(s) distributed with this work for additional
// information regarding copyright ownership.
//
// This program and the accompanying materials are made available under the
// terms of the Apache License Version 2.0 which is available at
// https://www.apache.org/licenses/LICENSE-2.0

//! DoIP domain value types.

use serde::Deserialize;

/// DoIP logical address.
#[derive(Debug, Clone, Copy, Deserialize)]
pub struct LogicalAddress(u16);

impl LogicalAddress {
    /// Creates a logical address from a raw `u16`.
    pub const fn new(addr: u16) -> Self {
        Self(addr)
    }

    /// Returns the address as big-endian bytes.
    pub fn to_be_bytes(self) -> [u8; 2] {
        self.0.to_be_bytes()
    }
}

impl From<u16> for LogicalAddress {
    fn from(addr: u16) -> Self {
        Self(addr)
    }
}

/// Vehicle identification number stored as 17 bytes.
#[derive(Debug, Clone, Copy, PartialEq, Deserialize)]
pub struct Vin([u8; 17]);

impl Vin {
    /// Creates a VIN from a 17-byte array.
    pub const fn new(bytes: [u8; 17]) -> Self {
        Self(bytes)
    }

    /// Returns the raw VIN bytes.
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }
}

/// Entity identifier stored as 6 bytes.
#[derive(Debug, Clone, Copy, PartialEq, Deserialize)]
pub struct Eid([u8; 6]);

impl Eid {
    /// Creates an EID from a 6-byte array.
    pub const fn new(bytes: [u8; 6]) -> Self {
        Self(bytes)
    }

    /// Returns the raw EID bytes.
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }
}

/// Group identifier stored as 6 bytes.
#[derive(Debug, Clone, Copy, Deserialize)]
pub struct Gid([u8; 6]);

impl Gid {
    /// Create a GID from a 6-byte array.
    pub const fn new(bytes: [u8; 6]) -> Self {
        Self(bytes)
    }
    /// Raw bytes for on-wire serialisation.
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }
}
