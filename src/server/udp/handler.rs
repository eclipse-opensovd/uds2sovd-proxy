//! UDP datagram parsing and dispatch.

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

use crate::doip::UdpDispatcher;
use crate::doip::constants::HEADER_LEN;
use crate::doip::error::Error;
use crate::doip::header::DoipHeader;
use crate::doip::message::{Response, UdpPayloadType, UdpRequest};

/// Parses and dispatches a single UDP DoIP datagram.
pub(crate) struct Handler {
    dispatcher: Arc<UdpDispatcher>,
}

impl Handler {
    /// Creates a UDP datagram handler backed by the given dispatcher.
    pub(crate) fn new(dispatcher: Arc<UdpDispatcher>) -> Self {
        Self { dispatcher }
    }

    /// Parses one UDP datagram and dispatches it to the registered handler.
    ///
    /// The datagram must contain exactly one complete DoIP frame:
    /// - at least an 8-byte generic header,
    /// - a payload length that matches the datagram body exactly,
    /// - and a payload type valid for UDP.
    ///
    /// Returns the response to send back, or an error if the datagram is malformed
    /// or the payload type is unrecognized.
    pub(crate) fn handle(&self, data: &[u8]) -> Result<Response, Error> {
        if data.len() < HEADER_LEN {
            return Err(Error::InvalidPayloadLength {
                expected: 0,
                actual: data.len(),
            });
        }

        let header = DoipHeader::parse(&data[..HEADER_LEN])?;
        let payload_len = header.payload_len;

        if data.len() != HEADER_LEN + payload_len {
            return Err(Error::InvalidPayloadLength {
                expected: payload_len as u32,
                actual: data.len().saturating_sub(HEADER_LEN),
            });
        }

        let payload_type =
            UdpPayloadType::try_from(header.payload_type_raw).map_err(Error::UnknownPayloadType)?;

        let udp_request = UdpRequest::new(
            payload_type,
            data[HEADER_LEN..HEADER_LEN + payload_len].to_vec(),
        );

        self.dispatcher.dispatch(udp_request)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::EcuConfig;
    use crate::doip::UdpDispatcher;
    use crate::doip::handlers::vehicle_identification::IdentifyVehicleHandler;
    use crate::doip::message::UdpPayloadType;
    use crate::doip::types::{Eid, Gid, LogicalAddress, Vin};

    /// Build a well-formed raw datagram with the given payload type and payload.
    fn raw_frame(payload_type: u16, payload: &[u8]) -> Vec<u8> {
        let mut buf = vec![0xFD, 0x02];
        buf.extend_from_slice(&payload_type.to_be_bytes());
        buf.extend_from_slice(&(payload.len() as u32).to_be_bytes());
        buf.extend_from_slice(payload);
        buf
    }

    fn empty_handler() -> Handler {
        Handler::new(Arc::new(UdpDispatcher::new()))
    }

    #[test]
    fn too_short_data_returns_error() {
        let result = empty_handler().handle(&[0xFD, 0x02, 0x00]);
        assert!(matches!(result, Err(Error::InvalidPayloadLength { .. })));
    }

    #[test]
    fn bad_protocol_version_returns_error() {
        let mut data = raw_frame(0x0001, &[]);
        data[0] = 0xAB;
        let result = empty_handler().handle(&data);
        assert!(matches!(result, Err(Error::InvalidHeaderVersion(0xAB))));
    }

    #[test]
    fn bad_inverse_version_returns_error() {
        let mut data = raw_frame(0x0001, &[]);
        data[1] = 0xAB;
        let result = empty_handler().handle(&data);
        assert!(matches!(result, Err(Error::InvalidInverseVersion(0xAB))));
    }

    #[test]
    fn unknown_payload_type_returns_error() {
        let data = raw_frame(0xDEAD, &[]);
        let result = empty_handler().handle(&data);
        assert!(matches!(result, Err(Error::UnknownPayloadType(0xDEAD))));
    }

    #[test]
    fn handle_rejects_truncated_payload() {
        // Header declares 4 bytes of payload but the datagram is truncated.
        let mut data = raw_frame(0x0001, &[0x00, 0x00, 0x00, 0x00]);
        data.truncate(10);
        let result = empty_handler().handle(&data);
        assert!(matches!(result, Err(Error::InvalidPayloadLength { .. })));
    }

    #[test]
    fn handle_rejects_trailing_bytes() {
        let mut data = raw_frame(0x0001, &[]);
        data.extend_from_slice(&[0xAA, 0xBB]);
        let result = empty_handler().handle(&data);
        assert!(matches!(
            result,
            Err(Error::InvalidPayloadLength {
                expected: 0,
                actual: 2
            })
        ));
    }

    #[test]
    fn handle_valid_vin_request_returns_announcement() {
        let mut dispatcher = UdpDispatcher::new();
        dispatcher.register(IdentifyVehicleHandler::new(
            EcuConfig::new(
                Vin::new(*b"00000000000000000"),
                Eid::new([0u8; 6]),
                Gid::new([0u8; 6]),
            ),
            LogicalAddress::new(0x0001),
        ));

        let handler = Handler::new(Arc::new(dispatcher));
        let data = raw_frame(UdpPayloadType::VehicleIdentificationRequest as u16, &[]);
        let resp = handler.handle(&data).unwrap();

        assert_eq!(
            resp.payload_type(),
            UdpPayloadType::VehicleAnnouncementResponse as u16
        );
        assert_eq!(resp.payload().len(), 32);
    }
}
