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
    constants::{ROUTING_ACTIVATION_CODE_SUCCESS, ROUTING_ACTIVATION_REQUEST_MIN_LEN},
    error::Error,
    message::{Response, TcpPayloadType, TcpRequest},
    types::LogicalAddress,
};

/// Handles `RoutingActivationRequest` messages.
pub struct RoutingActivationHandler {
    server_logical_address: LogicalAddress,
}

impl RoutingActivationHandler {
    /// Creates a routing-activation handler for the supplied server address.
    pub fn new(server_logical_address: LogicalAddress) -> Self {
        Self {
            server_logical_address,
        }
    }

    /// Builds a `RoutingActivationResponse` payload.
    fn activate(&self, client_address: u16, _activation_type: u8) -> Response {
        let mut payload = Vec::with_capacity(13);
        payload.extend_from_slice(&client_address.to_be_bytes());
        payload.extend_from_slice(&self.server_logical_address.to_be_bytes());
        payload.push(ROUTING_ACTIVATION_CODE_SUCCESS);
        payload.extend_from_slice(&[0u8; 4]); // reserved ISO
        payload.extend_from_slice(&[0u8; 4]); // reserved OEM
        Response::new(TcpPayloadType::RoutingActivationResponse as u16, payload)
    }
}

impl PayloadHandler<TcpPayloadType, TcpRequest> for RoutingActivationHandler {
    fn payload_type(&self) -> TcpPayloadType {
        TcpPayloadType::RoutingActivationRequest
    }

    fn handle(&self, tcp_request: TcpRequest) -> Result<Response, Error> {
        if tcp_request.payload().len() < ROUTING_ACTIVATION_REQUEST_MIN_LEN {
            return Err(Error::PayloadTooShort {
                expected: ROUTING_ACTIVATION_REQUEST_MIN_LEN,
                actual: tcp_request.payload().len(),
            });
        }
        let client_address =
            u16::from_be_bytes([tcp_request.payload()[0], tcp_request.payload()[1]]);
        let activation_type = tcp_request.payload()[2];
        Ok(self.activate(client_address, activation_type))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::doip::types::LogicalAddress;

    fn make_req(payload: Vec<u8>) -> TcpRequest {
        TcpRequest::new(TcpPayloadType::RoutingActivationRequest, payload)
    }

    #[test]
    fn handle_valid_request_returns_activation_success() {
        let handler = RoutingActivationHandler::new(LogicalAddress::new(0x0001));
        let resp = handler
            .handle(make_req(vec![0x00, 0x42, 0x00, 0, 0, 0, 0, 0, 0, 0, 0]))
            .unwrap();
        assert_eq!(
            resp.payload_type(),
            TcpPayloadType::RoutingActivationResponse as u16
        );
        assert_eq!(
            resp.payload()[4],
            0x10,
            "response code must be 0x10 (success)"
        );
        // client address echoed back
        assert_eq!(&resp.payload()[0..2], &[0x00, 0x42]);
        // server address
        assert_eq!(&resp.payload()[2..4], &[0x00, 0x01]);
    }

    #[test]
    fn handle_rejects_short_payload() {
        let handler = RoutingActivationHandler::new(LogicalAddress::new(0x0001));
        assert!(matches!(
            handler.handle(make_req(vec![0x00])),
            Err(Error::PayloadTooShort { .. })
        ));
    }

    #[test]
    fn handle_rejects_partial_payload() {
        let handler = RoutingActivationHandler::new(LogicalAddress::new(0x0001));
        assert!(matches!(
            handler.handle(make_req(vec![0x00, 0x42, 0x00])),
            Err(Error::PayloadTooShort {
                expected: 11,
                actual: 3
            })
        ));
    }
}
