// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 The Contributors to Eclipse OpenSOVD (see CONTRIBUTORS)
//
// See the NOTICE file(s) distributed with this work for additional
// information regarding copyright ownership.
//
// This program and the accompanying materials are made available under the
// terms of the Apache License Version 2.0 which is available at
// https://www.apache.org/licenses/LICENSE-2.0

use std::sync::Arc;

use crate::doip::{
    PayloadHandler,
    constants::{DIAG_ACK_HEADER_LEN, DIAG_MSG_MIN_PAYLOAD_LEN, DIAGNOSTIC_MESSAGE_ACK},
    error::Error,
    message::{Response, TcpPayloadType, TcpRequest},
};
use crate::proxy::SovdProxy;

/// Handles `DiagnosticMessage` requests.
///
/// The handler forwards the UDS payload to a [`SovdProxy`] and wraps the
/// returned bytes in a DoIP acknowledgment response.
pub struct DiagnosticsHandler {
    proxy: Arc<dyn SovdProxy>,
}

impl DiagnosticsHandler {
    /// Creates a diagnostic handler backed by the provided proxy.
    pub fn new(proxy: Arc<dyn SovdProxy>) -> Self {
        Self { proxy }
    }

    /// Forwards a diagnostic payload and builds the response frame.
    fn forward(&self, src: u16, tgt: u16, uds: &[u8]) -> Result<Response, Error> {
        let ecu_response = self.proxy.process(uds)?;

        let mut payload = Vec::with_capacity(DIAG_ACK_HEADER_LEN + ecu_response.len());
        payload.extend_from_slice(&tgt.to_be_bytes()); // server address
        payload.extend_from_slice(&src.to_be_bytes()); // client address
        payload.push(DIAGNOSTIC_MESSAGE_ACK);
        payload.extend_from_slice(&ecu_response);
        Ok(Response::new(
            TcpPayloadType::DiagnosticMessagePositiveAck as u16,
            payload,
        ))
    }
}

impl PayloadHandler<TcpPayloadType, TcpRequest> for DiagnosticsHandler {
    fn payload_type(&self) -> TcpPayloadType {
        TcpPayloadType::DiagnosticMessage
    }

    fn handle(&self, tcp_request: TcpRequest) -> Result<Response, Error> {
        if tcp_request.payload().len() < DIAG_MSG_MIN_PAYLOAD_LEN {
            return Err(Error::PayloadTooShort {
                expected: DIAG_MSG_MIN_PAYLOAD_LEN,
                actual: tcp_request.payload().len(),
            });
        }
        let source_address =
            u16::from_be_bytes([tcp_request.payload()[0], tcp_request.payload()[1]]);
        let target_address =
            u16::from_be_bytes([tcp_request.payload()[2], tcp_request.payload()[3]]);
        self.forward(source_address, target_address, &tcp_request.payload()[4..])
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::proxy::mock::MockProxy;

    #[test]
    fn handle_forwards_uds_and_returns_ack() {
        let handler = DiagnosticsHandler::new(Arc::new(MockProxy));
        let uds = vec![0x22, 0xF1, 0x90]; // ReadDataByIdentifier
        let mut payload = vec![0x00, 0x01, 0x10, 0x00]; // src=0x0001 tgt=0x1000
        payload.extend_from_slice(&uds);

        let resp = handler
            .handle(TcpRequest::new(TcpPayloadType::DiagnosticMessage, payload))
            .unwrap();

        assert_eq!(
            resp.payload_type(),
            TcpPayloadType::DiagnosticMessagePositiveAck as u16
        );
        assert_eq!(resp.payload()[4], 0x00, "ACK code must be 0x00");
        assert_eq!(&resp.payload()[5..], &uds, "MockProxy echoes UDS bytes");
    }

    #[test]
    fn handle_rejects_short_payload() {
        let handler = DiagnosticsHandler::new(Arc::new(MockProxy));
        let resp = handler.handle(TcpRequest::new(
            TcpPayloadType::DiagnosticMessage,
            vec![0x00, 0x01],
        ));
        assert!(matches!(resp, Err(Error::PayloadTooShort { .. })));
    }
}
