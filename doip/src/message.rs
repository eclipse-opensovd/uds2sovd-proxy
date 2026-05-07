/*
 * SPDX-License-Identifier: Apache-2.0
 * SPDX-FileCopyrightText: 2026 The Contributors to Eclipse OpenSOVD (see CONTRIBUTORS)
 *
 * See the NOTICE file(s) distributed with this work for additional
 * information regarding copyright ownership.
 *
 * This program and the accompanying materials are made available under the
 * terms of the Apache License Version 2.0 which is available at
 * https://www.apache.org/licenses/LICENSE-2.0
 */

//! `DoIP` wire-format message types, framing constants, and parsers (ISO 13400-2).
//!
//! Defines [`DoIpMessage`], [`PayloadType`], [`RoutingActivationRequest`], and
//! [`DiagnosticMessage`] — the byte-format types used throughout the `doip` crate.

use bytes::{BufMut, BytesMut};

/// `DoIP` protocol version per ISO 13400-2.
pub const DOIP_PROTOCOL_VERSION: u8 = 0x02;

/// `DoIP` header size in bytes: version (1) + inverse (1) + type (2) + length (4).
pub const DOIP_HEADER_SIZE: usize = 8;

/// Minimum routing activation request payload: source address (2) + type (1) + reserved (4).
const ROUTING_ACTIVATION_REQUEST_MIN_LEN: usize = 7;

/// Diagnostic message header size: source address (2) + target address (2).
pub const DIAGNOSTIC_MESSAGE_HEADER_SIZE: usize = 4;

/// Error returned when a raw `DoIP` value or byte slice cannot be parsed.
///
/// Parsing fails when the input is too short, the protocol version bytes
/// do not satisfy `version == 0x02 && inverse == !version`, or the raw
/// numeric value does not map to a known [`PayloadType`] variant.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ParseError;

impl std::fmt::Display for ParseError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Invalid or truncated DoIP wire payload")
    }
}

impl std::error::Error for ParseError {}

/// `DoIP` payload types defined in ISO 13400-2.
///
/// Each variant carries the 16-bit payload type code used on the wire.
#[repr(u16)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PayloadType {
    /// Generic `DoIP` header negative acknowledge
    GenericHeaderNack = 0x0000,
    /// Vehicle identification request
    VehicleIdentificationRequest = 0x0001,
    /// Vehicle identification request with EID
    VehicleIdentificationRequestWithEid = 0x0002,
    /// Vehicle identification request with VIN
    VehicleIdentificationRequestWithVin = 0x0003,
    /// Vehicle announcement/identification response
    VehicleAnnouncementIdentificationResponse = 0x0004,
    /// Routing activation request
    RoutingActivationRequest = 0x0005,
    /// Routing activation response
    RoutingActivationResponse = 0x0006,
    /// Alive check request
    AliveCheckRequest = 0x0007,
    /// Alive check response
    AliveCheckResponse = 0x0008,
    /// Diagnostic message
    DiagnosticMessage = 0x8001,
    /// Diagnostic message positive acknowledgement
    DiagnosticMessagePositiveAck = 0x8002,
    /// Diagnostic message negative acknowledgement
    DiagnosticMessageNegativeAck = 0x8003,
}

impl TryFrom<u16> for PayloadType {
    type Error = ParseError;

    /// Convert a raw `u16` wire value to a [`PayloadType`].
    ///
    /// # Errors
    ///
    /// Returns [`ParseError`] for unrecognised payload type codes.
    fn try_from(value: u16) -> Result<Self, Self::Error> {
        match value {
            0x0000 => Ok(Self::GenericHeaderNack),
            0x0001 => Ok(Self::VehicleIdentificationRequest),
            0x0002 => Ok(Self::VehicleIdentificationRequestWithEid),
            0x0003 => Ok(Self::VehicleIdentificationRequestWithVin),
            0x0004 => Ok(Self::VehicleAnnouncementIdentificationResponse),
            0x0005 => Ok(Self::RoutingActivationRequest),
            0x0006 => Ok(Self::RoutingActivationResponse),
            0x0007 => Ok(Self::AliveCheckRequest),
            0x0008 => Ok(Self::AliveCheckResponse),
            0x8001 => Ok(Self::DiagnosticMessage),
            0x8002 => Ok(Self::DiagnosticMessagePositiveAck),
            0x8003 => Ok(Self::DiagnosticMessageNegativeAck),
            _ => Err(ParseError),
        }
    }
}

/// `DoIP` message consisting of a header and variable-length payload.
///
/// The header contains the protocol version, inverse version byte,
/// 16-bit payload type, and 32-bit payload length per ISO 13400-2.
#[derive(Debug, Clone)]
pub struct DoIpMessage {
    /// Protocol version byte (typically [`DOIP_PROTOCOL_VERSION`]).
    pub protocol_version: u8,
    /// Raw 16-bit payload type code.
    pub payload_type: u16,
    /// Variable-length payload bytes.
    pub payload: Vec<u8>,
}

impl DoIpMessage {
    /// Create a new `DoIP` message with the given payload type and data.
    #[must_use]
    pub fn new(payload_type: PayloadType, payload: Vec<u8>) -> Self {
        Self {
            protocol_version: DOIP_PROTOCOL_VERSION,
            payload_type: payload_type as u16,
            payload,
        }
    }

    /// Serialize this message to wire-format bytes.
    #[must_use]
    #[allow(clippy::cast_possible_truncation)]
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut buf = BytesMut::with_capacity(DOIP_HEADER_SIZE.saturating_add(self.payload.len()));

        buf.put_u8(self.protocol_version);
        buf.put_u8(!self.protocol_version);
        buf.put_u16(self.payload_type);
        buf.put_u32(self.payload.len() as u32);
        buf.put_slice(&self.payload);

        buf.to_vec()
    }

    /// Get the typed [`PayloadType`] for this message's raw type code.
    ///
    /// Returns `None` for unrecognised payload type codes.
    #[must_use]
    pub fn payload_type_enum(&self) -> Option<PayloadType> {
        PayloadType::try_from(self.payload_type).ok()
    }
}

impl TryFrom<&[u8]> for DoIpMessage {
    type Error = ParseError;

    /// Parse a `DoIP` message from a raw byte buffer.
    ///
    /// Verifies the ISO 13400-2 protocol version bytes and that the declared
    /// payload length does not exceed the available data.
    ///
    /// # Errors
    ///
    /// Returns [`ParseError`] if the buffer is too short, the version bytes
    /// are invalid, or the declared payload length exceeds available data.
    fn try_from(data: &[u8]) -> Result<Self, Self::Error> {
        if data.len() < DOIP_HEADER_SIZE {
            return Err(ParseError);
        }

        let protocol_version = *data.first().ok_or(ParseError)?;
        let inverse_protocol_version = *data.get(1).ok_or(ParseError)?;

        // Verify protocol version per ISO 13400-2.
        if protocol_version != DOIP_PROTOCOL_VERSION || inverse_protocol_version != !protocol_version {
            return Err(ParseError);
        }

        let payload_type_bytes: [u8; 2] = data
            .get(2..4)
            .ok_or(ParseError)?
            .try_into()
            .map_err(|_| ParseError)?;
        let payload_type = u16::from_be_bytes(payload_type_bytes);

        let payload_length_bytes: [u8; 4] = data
            .get(4..8)
            .ok_or(ParseError)?
            .try_into()
            .map_err(|_| ParseError)?;
        let payload_length: usize = u32::from_be_bytes(payload_length_bytes)
            .try_into()
            .map_err(|_| ParseError)?;

        let end = DOIP_HEADER_SIZE.checked_add(payload_length).ok_or(ParseError)?;
        let payload = data.get(DOIP_HEADER_SIZE..end).ok_or(ParseError)?.to_vec();

        Ok(Self {
            protocol_version,
            payload_type,
            payload,
        })
    }
}

/// Parsed routing activation request (ISO 13400-2 Table 18).
#[derive(Debug)]
pub struct RoutingActivationRequest {
    /// Source address of the external test equipment.
    pub source_address: u16,
    /// Routing activation type (default / diagnostic / central security).
    pub activation_type: u8,
    /// Reserved bytes specified by ISO (OEM-specific use).
    /// TODO(doip): Use for OEM-specific routing activation handling.
    #[allow(dead_code)]
    pub reserved: u32,
}

impl TryFrom<&[u8]> for RoutingActivationRequest {
    type Error = ParseError;

    /// Parse a routing activation request from a `DoIP` payload
    /// (ISO 13400-2 Table 18).
    ///
    /// # Errors
    ///
    /// Returns [`ParseError`] if the payload is shorter than the minimum 7 bytes.
    fn try_from(payload: &[u8]) -> Result<Self, Self::Error> {
        if payload.len() < ROUTING_ACTIVATION_REQUEST_MIN_LEN {
            return Err(ParseError);
        }

        let sa: [u8; 2] = payload
            .get(0..2)
            .ok_or(ParseError)?
            .try_into()
            .map_err(|_| ParseError)?;
        let source_address = u16::from_be_bytes(sa);
        let activation_type = *payload.get(2).ok_or(ParseError)?;
        let res: [u8; 4] = payload
            .get(3..7)
            .ok_or(ParseError)?
            .try_into()
            .map_err(|_| ParseError)?;
        let reserved = u32::from_be_bytes(res);

        Ok(Self {
            source_address,
            activation_type,
            reserved,
        })
    }
}

/// Parsed diagnostic message (ISO 13400-2 Table 21).
#[derive(Debug)]
pub struct DiagnosticMessage {
    /// Source address of the sending entity.
    pub source_address: u16,
    /// Target address of the receiving entity.
    pub target_address: u16,
    /// UDS user data (service bytes).
    pub user_data: Vec<u8>,
}

impl TryFrom<&[u8]> for DiagnosticMessage {
    type Error = ParseError;

    /// Parse a diagnostic message from a `DoIP` payload (ISO 13400-2 Table 21).
    ///
    /// # Errors
    ///
    /// Returns [`ParseError`] if the payload is shorter than the minimum 4 bytes.
    fn try_from(payload: &[u8]) -> Result<Self, Self::Error> {
        if payload.len() < DIAGNOSTIC_MESSAGE_HEADER_SIZE {
            return Err(ParseError);
        }

        let sa: [u8; 2] = payload
            .get(0..2)
            .ok_or(ParseError)?
            .try_into()
            .map_err(|_| ParseError)?;
        let source_address = u16::from_be_bytes(sa);
        let ta: [u8; 2] = payload
            .get(2..4)
            .ok_or(ParseError)?
            .try_into()
            .map_err(|_| ParseError)?;
        let target_address = u16::from_be_bytes(ta);
        let user_data = payload.get(4..).unwrap_or_default().to_vec();

        Ok(Self {
            source_address,
            target_address,
            user_data,
        })
    }
}

impl From<DiagnosticMessage> for Vec<u8> {
    /// Serialise a [`DiagnosticMessage`] into a raw `DoIP` diagnostic payload.
    ///
    /// Layout: source address (2 bytes BE) + target address (2 bytes BE) + UDS data.
    fn from(msg: DiagnosticMessage) -> Self {
        let mut payload =
            Self::with_capacity(DIAGNOSTIC_MESSAGE_HEADER_SIZE.saturating_add(msg.user_data.len()));
        payload.extend_from_slice(&msg.source_address.to_be_bytes());
        payload.extend_from_slice(&msg.target_address.to_be_bytes());
        payload.extend_from_slice(&msg.user_data);
        payload
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn doip_message_serializes_header_and_payload_to_wire_bytes() {
        let msg = DoIpMessage::new(PayloadType::DiagnosticMessage, vec![0x01, 0x02, 0x03]);
        let bytes = msg.to_bytes();

        let (&b0, &b1) = (bytes.first().expect("b0"), bytes.get(1).expect("b1"));
        let pt: [u8; 2] = bytes.get(2..4).expect("pt").try_into().expect("2b");
        let len_field: [u8; 4] = bytes.get(4..8).expect("len").try_into().expect("4b");
        let rest = bytes.get(8..).expect("rest");
        assert_eq!(b0, DOIP_PROTOCOL_VERSION);
        assert_eq!(b1, !DOIP_PROTOCOL_VERSION);
        assert_eq!(u16::from_be_bytes(pt), 0x8001);
        assert_eq!(u32::from_be_bytes(len_field), 3);
        assert_eq!(rest, &[0x01, 0x02, 0x03]);
    }

    #[test]
    fn doip_message_parses_from_valid_wire_bytes() {
        let bytes = vec![
            0x02, 0xFD, // Version and inverse
            0x80, 0x01, // Payload type (DiagnosticMessage)
            0x00, 0x00, 0x00, 0x03, // Payload length
            0x01, 0x02, 0x03, // Payload
        ];

        let msg = DoIpMessage::try_from(bytes.as_slice()).expect("failed to parse valid DoIP message");
        assert_eq!(msg.protocol_version, 0x02);
        assert_eq!(msg.payload_type, 0x8001);
        assert_eq!(msg.payload, vec![0x01, 0x02, 0x03]);
    }

    #[test]
    fn diagnostic_message_parses_source_target_and_user_data() {
        let payload = vec![
            0x0E, 0x80, // Source address
            0x00, 0x01, // Target address
            0x22, 0xF1, 0x90, // UDS data
        ];

        let diag_msg = DiagnosticMessage::try_from(payload.as_slice())
            .expect("failed to parse valid diagnostic message");
        assert_eq!(diag_msg.source_address, 0x0E80);
        assert_eq!(diag_msg.target_address, 0x0001);
        assert_eq!(diag_msg.user_data, vec![0x22, 0xF1, 0x90]);
    }

    #[test]
    fn routing_activation_request_parses_source_address_and_type() {
        let payload = vec![
            0x0E, 0x80, // Source address
            0x00, // Activation type
            0x00, 0x00, 0x00, 0x00, // Reserved
        ];

        let req = RoutingActivationRequest::try_from(payload.as_slice())
            .expect("failed to parse valid routing activation request");
        assert_eq!(req.source_address, 0x0E80);
        assert_eq!(req.activation_type, 0x00);
    }

    #[test]
    fn doip_message_survives_serialize_deserialize_roundtrip() {
        let original = DoIpMessage::new(
            PayloadType::RoutingActivationRequest,
            vec![0x0E, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00],
        );
        let bytes = original.to_bytes();
        let parsed =
            DoIpMessage::try_from(bytes.as_slice()).expect("failed to parse roundtrip DoIP message");
        assert_eq!(parsed.protocol_version, original.protocol_version);
        assert_eq!(parsed.payload_type, original.payload_type);
        assert_eq!(parsed.payload, original.payload);
    }

    #[test]
    fn doip_message_returns_parse_error_for_too_short_input() {
        assert!(DoIpMessage::try_from([0x02u8, 0xFDu8].as_slice()).is_err());
        assert!(DoIpMessage::try_from([0u8; 0].as_slice()).is_err());
    }

    #[test]
    fn doip_message_returns_parse_error_for_invalid_version_bytes() {
        let bytes = vec![0x03, 0xFC, 0x80, 0x01, 0x00, 0x00, 0x00, 0x00];
        assert!(DoIpMessage::try_from(bytes.as_slice()).is_err());
    }

    #[test]
    fn doip_message_returns_parse_error_when_payload_length_exceeds_data() {
        let bytes = vec![
            0x02, 0xFD, 0x80, 0x01, 0x00, 0x00, 0x00, 0x05, // Says 5 bytes but only 2 follow
            0x01, 0x02,
        ];
        assert!(DoIpMessage::try_from(bytes.as_slice()).is_err());
    }

    #[test]
    fn payload_type_try_from_u16_maps_known_and_unknown_codes() {
        assert_eq!(PayloadType::try_from(0x0005u16), Ok(PayloadType::RoutingActivationRequest));
        assert_eq!(PayloadType::try_from(0x8001u16), Ok(PayloadType::DiagnosticMessage));
        assert_eq!(PayloadType::try_from(0xFFFFu16), Err(ParseError));
    }

    #[test]
    fn diagnostic_message_serializes_to_expected_payload_bytes() {
        let payload: Vec<u8> = DiagnosticMessage {
            source_address: 0x0E80,
            target_address: 0x1000,
            user_data: vec![0x22, 0xF1, 0x90],
        }
        .into();
        assert_eq!(payload, vec![0x0E, 0x80, 0x10, 0x00, 0x22, 0xF1, 0x90]);
    }

    #[test]
    fn diagnostic_message_returns_parse_error_for_too_short_payload() {
        assert!(DiagnosticMessage::try_from([0x0Eu8, 0x80u8].as_slice()).is_err());
    }

    #[test]
    fn routing_activation_request_returns_parse_error_for_too_short_payload() {
        assert!(RoutingActivationRequest::try_from([0x0Eu8, 0x80u8].as_slice()).is_err());
    }
}
