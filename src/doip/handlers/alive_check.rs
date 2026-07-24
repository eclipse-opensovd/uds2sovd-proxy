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
    error::Error,
    message::{Response, TcpPayloadType, TcpRequest},
    types::LogicalAddress,
};

/// Handles `AliveCheckRequest` messages.
pub struct AliveCheckHandler {
    logical_address: LogicalAddress,
}

impl AliveCheckHandler {
    /// Creates an alive-check handler for the supplied logical address.
    pub fn new(logical_address: LogicalAddress) -> Self {
        Self { logical_address }
    }

    /// Builds an `AliveCheckResponse` payload.
    fn respond(&self) -> Response {
        let mut payload = Vec::with_capacity(2);
        payload.extend_from_slice(&self.logical_address.to_be_bytes());
        Response::new(TcpPayloadType::AliveCheckResponse as u16, payload)
    }
}

impl PayloadHandler<TcpPayloadType, TcpRequest> for AliveCheckHandler {
    fn payload_type(&self) -> TcpPayloadType {
        TcpPayloadType::AliveCheckRequest
    }
    fn handle(&self, tcp_request: TcpRequest) -> Result<Response, Error> {
        if !tcp_request.payload().is_empty() {
            return Err(Error::UnexpectedPayload {
                expected: 0,
                actual: tcp_request.payload().len(),
            });
        }
        Ok(self.respond())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::doip::types::LogicalAddress;

    #[test]
    fn handle_empty_payload_returns_logical_address() {
        let handler = AliveCheckHandler::new(LogicalAddress::new(0x0001));
        let req = TcpRequest::new(TcpPayloadType::AliveCheckRequest, vec![]);
        let resp = handler.handle(req).unwrap();
        assert_eq!(
            resp.payload_type(),
            TcpPayloadType::AliveCheckResponse as u16
        );
        assert_eq!(resp.payload(), &[0x00, 0x01]);
    }

    #[test]
    fn handle_encodes_address_big_endian() {
        let handler = AliveCheckHandler::new(LogicalAddress::new(0x1234));
        let req = TcpRequest::new(TcpPayloadType::AliveCheckRequest, vec![]);
        let resp = handler.handle(req).unwrap();
        assert_eq!(resp.payload(), &[0x12, 0x34]);
    }

    #[test]
    fn handle_rejects_non_empty_payload() {
        let handler = AliveCheckHandler::new(LogicalAddress::new(0x0001));
        let req = TcpRequest::new(TcpPayloadType::AliveCheckRequest, vec![0xAA]);
        let resp = handler.handle(req);
        assert!(matches!(
            resp,
            Err(Error::UnexpectedPayload {
                expected: 0,
                actual: 1
            })
        ));
    }
}
