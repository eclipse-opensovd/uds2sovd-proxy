// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 The Contributors to Eclipse OpenSOVD (see CONTRIBUTORS)
//
// See the NOTICE file(s) distributed with this work for additional
// information regarding copyright ownership.
//
// This program and the accompanying materials are made available under the
// terms of the Apache License Version 2.0 which is available at
// https://www.apache.org/licenses/LICENSE-2.0

use crate::doip::{
    PayloadHandler,
    constants::{DOIP_NODE_TYPE, ENTITY_STATUS_RESPONSE_LEN},
    error::Error,
    message::{Response, UdpPayloadType, UdpRequest},
};

/// Handles `DoipEntityStatusRequest` messages.
pub struct EntityStatusHandler {
    /// Maximum concurrent TCP connections reported in the response.
    max_connections: u8,

    /// Maximum DoIP data size reported in the response.
    max_data_size: u32,
}

impl EntityStatusHandler {
    /// Creates an entity-status handler with the reported capacity values.
    pub fn new(max_connections: u8, max_data_size: u32) -> Self {
        Self {
            max_connections,
            max_data_size,
        }
    }
}

impl PayloadHandler<UdpPayloadType, UdpRequest> for EntityStatusHandler {
    fn payload_type(&self) -> UdpPayloadType {
        UdpPayloadType::DoipEntityStatusRequest
    }

    fn handle(&self, udp_request: UdpRequest) -> Result<Response, Error> {
        if !udp_request.payload().is_empty() {
            return Err(Error::UnexpectedPayload {
                expected: 0,
                actual: udp_request.payload().len(),
            });
        }
        let mut payload = Vec::with_capacity(ENTITY_STATUS_RESPONSE_LEN);
        payload.push(DOIP_NODE_TYPE);
        payload.push(self.max_connections);
        payload.push(0x00);
        payload.extend_from_slice(&self.max_data_size.to_be_bytes());
        Ok(Response::new(
            UdpPayloadType::DoipEntityStatusResponse as u16,
            payload,
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn handle_returns_7_byte_status_response() {
        let handler = EntityStatusHandler::new(10, 65_535);
        let req = UdpRequest::new(UdpPayloadType::DoipEntityStatusRequest, vec![]);
        let resp = handler.handle(req).unwrap();

        assert_eq!(
            resp.payload_type(),
            UdpPayloadType::DoipEntityStatusResponse as u16
        );
        assert_eq!(resp.payload().len(), ENTITY_STATUS_RESPONSE_LEN);
        assert_eq!(resp.payload()[0], DOIP_NODE_TYPE);
        assert_eq!(resp.payload()[1], 10);
        assert_eq!(resp.payload()[2], 0x00);
        assert_eq!(
            u32::from_be_bytes([
                resp.payload()[3],
                resp.payload()[4],
                resp.payload()[5],
                resp.payload()[6]
            ]),
            65_535
        );
    }

    #[test]
    fn handle_rejects_non_empty_payload() {
        let handler = EntityStatusHandler::new(10, 65_535);
        let req = UdpRequest::new(UdpPayloadType::DoipEntityStatusRequest, vec![0x01]);
        assert!(handler.handle(req).is_err());
    }
}
