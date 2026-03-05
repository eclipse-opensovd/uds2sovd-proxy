/*
 * Copyright (c) 2026 The Contributors to Eclipse OpenSOVD (see CONTRIBUTORS)
 *
 * See the NOTICE file(s) distributed with this work for additional
 * information regarding copyright ownership.
 *
 * This program and the accompanying materials are made available under the
 * terms of the Apache License Version 2.0 which is available at
 * https://www.apache.org/licenses/LICENSE-2.0
 *
 * SPDX-License-Identifier: Apache-2.0
 */
//! Alive Check handlers (ISO 13400-2)

use super::{DoipParseable, DoipSerializable};
use crate::DoipError;
use bytes::{BufMut, BytesMut};
use tracing::warn;

// Alive Check Request (0x0007) - no payload
// Server sends this to check if tester is still connected
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Request;

impl DoipParseable for Request {
    fn parse(_payload: &[u8]) -> std::result::Result<Self, DoipError> {
        Ok(Self)
    }
}

impl DoipSerializable for Request {
    fn serialized_len(&self) -> Option<usize> {
        Some(0)
    }

    fn write_to(&self, _buf: &mut BytesMut) {}
}

// Alive Check Response (0x0008) - 2 byte source address
// Tester responds with its logical address
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Response {
    source_address: u16,
}

impl DoipParseable for Response {
    fn parse(payload: &[u8]) -> std::result::Result<Self, DoipError> {
        let bytes: [u8; 2] = payload
            .get(..Self::LEN)
            .and_then(|s| s.try_into().ok())
            .ok_or_else(|| {
                let e = DoipError::PayloadTooShort {
                    expected: Self::LEN,
                    actual: payload.len(),
                };
                warn!("AliveCheck Response parse failed: {}", e);
                e
            })?;

        let source_address = u16::from_be_bytes(bytes);
        Ok(Self { source_address })
    }
}

impl DoipSerializable for Response {
    fn serialized_len(&self) -> Option<usize> {
        Some(Self::LEN)
    }

    fn write_to(&self, buf: &mut BytesMut) {
        buf.put_u16(self.source_address);
    }
}

impl Response {
    pub const LEN: usize = 2;

    #[must_use]
    pub fn new(source_address: u16) -> Self {
        Self { source_address }
    }

    /// The logical source address of the tester
    #[must_use]
    pub fn source_address(&self) -> u16 {
        self.source_address
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::doip::{DoipParseable, DoipSerializable};

    #[test]
    fn parse_request() {
        let req = Request::parse(&[]).unwrap();
        assert_eq!(req, Request);
    }

    #[test]
    fn request_empty_payload() {
        let req = Request;
        let bytes = req.to_bytes();
        assert!(bytes.is_empty());
    }

    #[test]
    fn parse_response() {
        let payload = [0x0E, 0x80];
        let resp = Response::parse(&payload).unwrap();
        assert_eq!(resp.source_address, 0x0E80);
    }

    #[test]
    fn reject_short_response() {
        let short = [0x0E];
        assert!(Response::parse(&short).is_err());
    }

    #[test]
    fn build_response() {
        let resp = Response::new(0x0E80);
        let bytes = resp.to_bytes();

        assert_eq!(bytes.len(), 2);
        assert_eq!(&bytes[..], &[0x0E, 0x80]);
    }

    #[test]
    fn roundtrip_response() {
        let original = Response::new(0x0F00);
        let bytes = original.to_bytes();
        let parsed = Response::parse(&bytes).unwrap();
        assert_eq!(original, parsed);
    }
}
