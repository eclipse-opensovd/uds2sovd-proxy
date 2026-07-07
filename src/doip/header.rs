// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 The Contributors to Eclipse OpenSOVD (see CONTRIBUTORS)
//
// See the NOTICE file(s) distributed with this work for additional
// information regarding copyright ownership.
//
// This program and the accompanying materials are made available under the
// terms of the Apache License Version 2.0 which is available at
// https://www.apache.org/licenses/LICENSE-2.0

//! DoIP generic header parsing.

use crate::doip::constants::{HEADER_LEN, INVERSE_VERSION, PROTOCOL_VERSION};
use crate::doip::error::Error;

/// Parsed DoIP generic header.
///
/// Contains the raw payload type and declared payload length.
#[derive(Debug, Clone, Copy)]
pub struct DoipHeader {
    /// Raw payload type from the header.
    pub payload_type_raw: u16,
    /// Declared payload length.
    pub payload_len: usize,
}

impl DoipHeader {
    /// Parses an 8-byte DoIP generic header.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidHeaderVersion`] or [`Error::InvalidInverseVersion`]
    /// if the version fields are invalid.
    pub fn parse(data: &[u8]) -> Result<Self, Error> {
        debug_assert!(
            data.len() >= HEADER_LEN,
            "DoipHeader::parse requires at least {HEADER_LEN} bytes, got {}",
            data.len()
        );

        if data[0] != PROTOCOL_VERSION {
            return Err(Error::InvalidHeaderVersion(data[0]));
        }
        if data[1] != INVERSE_VERSION {
            return Err(Error::InvalidInverseVersion(data[1]));
        }

        let payload_type_raw = u16::from_be_bytes([data[2], data[3]]);
        let payload_len = u32::from_be_bytes([data[4], data[5], data[6], data[7]]) as usize;

        Ok(Self {
            payload_type_raw,
            payload_len,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn valid_header(payload_type: u16, payload_len: u32) -> Vec<u8> {
        let mut buf = vec![PROTOCOL_VERSION, INVERSE_VERSION];
        buf.extend_from_slice(&payload_type.to_be_bytes());
        buf.extend_from_slice(&payload_len.to_be_bytes());
        buf
    }

    #[test]
    fn parse_valid_header() {
        let data = valid_header(0x0005, 11);
        let header = DoipHeader::parse(&data).unwrap();
        assert_eq!(header.payload_type_raw, 0x0005);
        assert_eq!(header.payload_len, 11);
    }

    #[test]
    fn parse_rejects_bad_version() {
        let mut data = valid_header(0x0007, 0);
        data[0] = 0x01;
        assert!(matches!(
            DoipHeader::parse(&data),
            Err(Error::InvalidHeaderVersion(0x01))
        ));
    }

    #[test]
    fn parse_rejects_bad_inverse() {
        let mut data = valid_header(0x0007, 0);
        data[1] = 0xAB;
        assert!(matches!(
            DoipHeader::parse(&data),
            Err(Error::InvalidInverseVersion(0xAB))
        ));
    }

    #[test]
    fn parse_preserves_large_payload_len() {
        let data = valid_header(0x8001, 65_536);
        let header = DoipHeader::parse(&data).unwrap();
        assert_eq!(header.payload_len, 65_536);
    }
}
