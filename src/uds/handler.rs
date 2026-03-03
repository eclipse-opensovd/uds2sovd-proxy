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

//! UDS Handler Trait
//!
//! Defines the interface between `DoIP` transport and UDS processing.
//! The `DoIP` server extracts UDS bytes from `DoIP` frames and delegates
//! to the handler. The handler returns UDS response bytes.

use bytes::Bytes;

/// UDS Service IDs (ISO 14229-1:2020)
pub mod service_id {
    pub const DIAGNOSTIC_SESSION_CONTROL: u8 = 0x10;
    pub const ECU_RESET: u8 = 0x11;
    pub const SECURITY_ACCESS: u8 = 0x27;
    pub const COMMUNICATION_CONTROL: u8 = 0x28;
    pub const TESTER_PRESENT: u8 = 0x3E;
    pub const CONTROL_DTC_SETTING: u8 = 0x85;
    pub const READ_DATA_BY_IDENTIFIER: u8 = 0x22;
    pub const WRITE_DATA_BY_IDENTIFIER: u8 = 0x2E;
    pub const ROUTINE_CONTROL: u8 = 0x31;
    pub const REQUEST_DOWNLOAD: u8 = 0x34;
    pub const REQUEST_UPLOAD: u8 = 0x35;
    pub const TRANSFER_DATA: u8 = 0x36;
    pub const REQUEST_TRANSFER_EXIT: u8 = 0x37;
    pub const READ_DTC_INFORMATION: u8 = 0x19;
    pub const CLEAR_DTC_INFORMATION: u8 = 0x14;
}

/// UDS request extracted from `DoIP` diagnostic message
#[derive(Debug, Clone)]
pub struct UdsRequest {
    pub source_address: u16,
    pub target_address: u16,
    pub payload: Bytes,
}

impl UdsRequest {
    #[must_use]
    pub fn new(source: u16, target: u16, payload: Bytes) -> Self {
        Self {
            source_address: source,
            target_address: target,
            payload,
        }
    }

    /// Returns the UDS Service ID, which is the first byte of the UDS payload
    /// per ISO 14229-1:2020 (UDS). None is returned for empty payloads.
    pub fn service_id(&self) -> Option<u8> {
        self.payload.first().copied()
    }
}

/// UDS response to be wrapped in `DoIP` diagnostic message
#[derive(Debug, Clone)]
pub struct UdsResponse {
    pub source_address: u16,
    pub target_address: u16,
    pub payload: Bytes,
}

impl UdsResponse {
    #[must_use]
    pub fn new(source: u16, target: u16, payload: Bytes) -> Self {
        Self {
            source_address: source,
            target_address: target,
            payload,
        }
    }
}

/// Trait for handling UDS requests
///
/// Implement this trait to connect the `DoIP` server to a UDS backend
/// (e.g., UDS2SOVD converter, ODX/MDD handler, or ECU simulator)
pub trait UdsHandler: Send + Sync {
    fn handle(&self, request: UdsRequest) -> UdsResponse;
}

#[cfg(test)]
mod tests {
    use super::*;
    use bytes::Bytes;

    #[test]
    fn uds_request_service_id() {
        let request = UdsRequest::new(0x0E00, 0x1000, Bytes::from(vec![0x10, 0x01]));
        assert_eq!(request.service_id(), Some(0x10));

        let empty = UdsRequest::new(0x0E00, 0x1000, Bytes::new());
        assert_eq!(empty.service_id(), None);
    }

    #[test]
    fn uds_response_new_sets_payload() {
        let payload = Bytes::from(vec![0x62, 0x01]);
        let response = UdsResponse::new(0x1000, 0x0E00, payload.clone());

        assert_eq!(response.source_address, 0x1000);
        assert_eq!(response.target_address, 0x0E00);
        assert_eq!(response.payload, payload);
    }
}
