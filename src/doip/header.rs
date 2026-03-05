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

//! `DoIP` Header Types
//!
//! Defines the core `DoIP` protocol types for header parsing and message structures
//! according to ISO 13400-2:2019.
//!
//! The `DoIP` header consists of 8 bytes:
//! - Protocol version (1 byte) + inverse version (1 byte)
//! - Payload type (2 bytes, big-endian)
//! - Payload length (4 bytes, big-endian)
//!
//! This module accepts protocol versions 0x01, 0x02, 0x03, and 0xFF to support
//! both ISO 13400-2:2012 and ISO 13400-2:2019 specifications.
//!
//! See [`codec`](super::codec) for the Tokio TCP framing codec.

use bytes::{BufMut, Bytes, BytesMut};
use tracing::{debug, warn};

/// Generic Header NACK codes (ISO 13400-2:2019 Table 17)
///
/// Negative acknowledgment codes sent in Generic `DoIP` Header NACK (payload type 0x0000)
/// when the `DoIP` entity cannot process a received message due to header-level issues.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum GenericNackCode {
    IncorrectPatternFormat = 0x00,
    UnknownPayloadType = 0x01,
    MessageTooLarge = 0x02,
    OutOfMemory = 0x03,
    InvalidPayloadLength = 0x04,
}

impl TryFrom<u8> for GenericNackCode {
    type Error = u8;

    fn try_from(value: u8) -> std::result::Result<Self, Self::Error> {
        match value {
            0x00 => Ok(Self::IncorrectPatternFormat),
            0x01 => Ok(Self::UnknownPayloadType),
            0x02 => Ok(Self::MessageTooLarge),
            0x03 => Ok(Self::OutOfMemory),
            0x04 => Ok(Self::InvalidPayloadLength),
            other => Err(other),
        }
    }
}

/// `DoIP` protocol version 0x01 (legacy, pre-ISO 13400-2:2012)
pub const PROTOCOL_VERSION_V1: u8 = 0x01;
/// Default `DoIP` protocol version 0x02 (ISO 13400-2:2012 / 2019)
pub const DEFAULT_PROTOCOL_VERSION: u8 = 0x02;
/// `DoIP` protocol version 0x03 (ISO 13400-2:2019 update)
pub const PROTOCOL_VERSION_V3: u8 = 0x03;
/// Wildcard/default protocol version (ISO 13400-2:2019 – accept any version)
pub const DOIP_VERSION_DEFAULT: u8 = 0xFF;
/// XOR mask used to compute and verify the inverse version byte in the `DoIP` header.
/// The header requires `version XOR inverse_version == 0xFF`.
pub const DOIP_HEADER_VERSION_MASK: u8 = 0xFF;
/// Inverse of default protocol version for header validation
pub const DEFAULT_PROTOCOL_VERSION_INV: u8 = DEFAULT_PROTOCOL_VERSION ^ DOIP_HEADER_VERSION_MASK;
/// Size of `DoIP` header in bytes (ISO 13400-2:2019 Section 6)
pub const DOIP_HEADER_LENGTH: usize = 8;
/// Maximum `DoIP` message size (4MB) - provides `DoS` protection while allowing
/// large diagnostic data transfers. Can be customized via `DoipCodec::with_max_payload_size()`.
pub const MAX_DOIP_MESSAGE_SIZE: u32 = 0x0040_0000; // 4MB

/// `DoIP` Payload Types (ISO 13400-2:2019 Table 16)
///
/// Identifies the type of message carried in the `DoIP` payload.
/// Supports diagnostic messages (0x8001), routing activation (0x0005-0x0006),
/// vehicle identification (0x0001-0x0004), alive check (0x0007-0x0008),
/// and diagnostic power mode requests (0x4003-0x4004).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u16)]
pub enum PayloadType {
    GenericNack = 0x0000,
    VehicleIdentificationRequest = 0x0001,
    VehicleIdentificationRequestWithEid = 0x0002,
    VehicleIdentificationRequestWithVin = 0x0003,
    VehicleIdentificationResponse = 0x0004,
    RoutingActivationRequest = 0x0005,
    RoutingActivationResponse = 0x0006,
    AliveCheckRequest = 0x0007,
    AliveCheckResponse = 0x0008,
    DoipEntityStatusRequest = 0x4001,
    DoipEntityStatusResponse = 0x4002,
    DiagnosticPowerModeRequest = 0x4003,
    DiagnosticPowerModeResponse = 0x4004,
    DiagnosticMessage = 0x8001,
    DiagnosticMessagePositiveAck = 0x8002,
    DiagnosticMessageNegativeAck = 0x8003,
}

impl TryFrom<u16> for PayloadType {
    type Error = u16;

    fn try_from(value: u16) -> std::result::Result<Self, Self::Error> {
        match value {
            0x0000 => Ok(Self::GenericNack),
            0x0001 => Ok(Self::VehicleIdentificationRequest),
            0x0002 => Ok(Self::VehicleIdentificationRequestWithEid),
            0x0003 => Ok(Self::VehicleIdentificationRequestWithVin),
            0x0004 => Ok(Self::VehicleIdentificationResponse),
            0x0005 => Ok(Self::RoutingActivationRequest),
            0x0006 => Ok(Self::RoutingActivationResponse),
            0x0007 => Ok(Self::AliveCheckRequest),
            0x0008 => Ok(Self::AliveCheckResponse),
            0x4001 => Ok(Self::DoipEntityStatusRequest),
            0x4002 => Ok(Self::DoipEntityStatusResponse),
            0x4003 => Ok(Self::DiagnosticPowerModeRequest),
            0x4004 => Ok(Self::DiagnosticPowerModeResponse),
            0x8001 => Ok(Self::DiagnosticMessage),
            0x8002 => Ok(Self::DiagnosticMessagePositiveAck),
            0x8003 => Ok(Self::DiagnosticMessageNegativeAck),
            other => Err(other),
        }
    }
}

impl From<PayloadType> for u16 {
    fn from(pt: PayloadType) -> u16 {
        pt as u16
    }
}

impl PayloadType {
    /// Returns minimum payload length for this payload type (ISO 13400-2:2019 Section 7)
    ///
    /// Each payload type has a defined minimum length to be considered valid.
    /// For example, `DiagnosticMessage` requires at least 5 bytes (source address,
    /// target address, and at least 1 UDS data byte).
    #[must_use]
    pub const fn min_payload_length(self) -> usize {
        match self {
            Self::VehicleIdentificationRequest
            | Self::AliveCheckRequest
            | Self::DoipEntityStatusRequest
            | Self::DiagnosticPowerModeRequest => 0,
            Self::GenericNack | Self::DiagnosticPowerModeResponse => 1,
            Self::AliveCheckResponse => 2,
            Self::DoipEntityStatusResponse => 3,
            Self::DiagnosticMessage
            | Self::DiagnosticMessagePositiveAck
            | Self::DiagnosticMessageNegativeAck => 5,
            Self::VehicleIdentificationRequestWithEid => 6,
            Self::RoutingActivationRequest => 7,
            Self::RoutingActivationResponse => 9,
            Self::VehicleIdentificationRequestWithVin => 17,
            Self::VehicleIdentificationResponse => 32,
        }
    }
}

/// `DoIP` Header Structure (ISO 13400-2:2019 Section 6)
///
/// Represents the 8-byte generic `DoIP` header that precedes every `DoIP` message.
/// The header uses big-endian byte order for multi-byte fields.
///
/// The `payload_type` field is stored as `u16` rather than `PayloadType` enum to allow
/// receiving and processing unknown/future payload types. This follows the robustness
/// principle: be liberal in what you accept. Unknown types trigger `GenericNackCode`
/// during validation but don't cause parsing failures.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DoipHeader {
    version: u8,
    inverse_version: u8,
    payload_type: u16,
    payload_length: u32,
}

impl DoipHeader {
    /// Parse a `DoIP` header from a byte slice
    ///
    /// # Errors
    /// Returns [`crate::DoipError::InvalidHeader`] if data is less than 8 bytes.
    pub(crate) fn parse(data: &[u8]) -> std::result::Result<Self, crate::DoipError> {
        let header: [u8; DOIP_HEADER_LENGTH] = data
            .get(..DOIP_HEADER_LENGTH)
            .and_then(|s| s.try_into().ok())
            .ok_or_else(|| {
                crate::DoipError::InvalidHeader(format!(
                    "DoIP header too short: expected {}, got {}",
                    DOIP_HEADER_LENGTH,
                    data.len()
                ))
            })?;

        Ok(Self {
            version: header[0],
            inverse_version: header[1],
            payload_type: u16::from_be_bytes([header[2], header[3]]),
            payload_length: u32::from_be_bytes([header[4], header[5], header[6], header[7]]),
        })
    }

    pub fn validate(&self) -> Option<GenericNackCode> {
        debug!(
            "Validating DoIP header: version=0x{:02X}, inverse=0x{:02X}, type=0x{:04X}, len={}",
            self.version, self.inverse_version, self.payload_type, self.payload_length
        );

        // Accept DoIP protocol versions V1, V2, V3 (and wildcard 0xFF for default/any)
        // ISO 13400-2:2012 uses V2, ISO 13400-2:2019 uses V3
        let valid_version = matches!(
            self.version,
            PROTOCOL_VERSION_V1
                | DEFAULT_PROTOCOL_VERSION
                | PROTOCOL_VERSION_V3
                | DOIP_VERSION_DEFAULT
        );
        if !valid_version {
            warn!("Invalid DoIP version: 0x{:02X}", self.version);
            return Some(GenericNackCode::IncorrectPatternFormat);
        }

        // Check version XOR inverse_version == DOIP_HEADER_VERSION_MASK (0xFF)
        if self.version ^ self.inverse_version != DOIP_HEADER_VERSION_MASK {
            warn!(
                "Version/inverse mismatch: 0x{:02X} ^ 0x{:02X} = 0x{:02X} (expected 0x{:02X})",
                self.version,
                self.inverse_version,
                self.version ^ self.inverse_version,
                DOIP_HEADER_VERSION_MASK,
            );
            return Some(GenericNackCode::IncorrectPatternFormat);
        }

        let Some(payload_type) = PayloadType::try_from(self.payload_type).ok() else {
            warn!("Unknown payload type: 0x{:04X}", self.payload_type);
            return Some(GenericNackCode::UnknownPayloadType);
        };

        if self.payload_length > MAX_DOIP_MESSAGE_SIZE {
            warn!("Message too large: {} bytes", self.payload_length);
            return Some(GenericNackCode::MessageTooLarge);
        }
        let Ok(payload_len_usize) = usize::try_from(self.payload_length) else {
            return Some(GenericNackCode::MessageTooLarge);
        };
        if payload_len_usize < payload_type.min_payload_length() {
            warn!(
                "Payload too short for {:?}: {} < {}",
                payload_type,
                self.payload_length,
                payload_type.min_payload_length()
            );
            return Some(GenericNackCode::InvalidPayloadLength);
        }

        None
    }

    #[must_use]
    pub fn is_valid(&self) -> bool {
        self.validate().is_none()
    }

    /// Returns the total message length (header + payload), or `None` if
    /// `payload_length` overflows `usize` (impossible on 32/64-bit platforms,
    /// but handled explicitly to avoid any panic path).
    #[must_use]
    pub fn message_length(&self) -> Option<usize> {
        usize::try_from(self.payload_length)
            .ok()
            .map(|pl| DOIP_HEADER_LENGTH.saturating_add(pl))
    }

    /// Serialize header to bytes
    #[must_use]
    pub fn to_bytes(&self) -> Bytes {
        let mut buf = BytesMut::with_capacity(DOIP_HEADER_LENGTH);
        self.write_to(&mut buf);
        buf.freeze()
    }

    pub fn write_to(&self, buf: &mut BytesMut) {
        buf.put_u8(self.version);
        buf.put_u8(self.inverse_version);
        buf.put_u16(self.payload_type);
        buf.put_u32(self.payload_length);
    }

    /// Protocol version byte
    #[must_use]
    pub fn version(&self) -> u8 {
        self.version
    }

    /// Inverted protocol version byte
    #[must_use]
    pub fn inverse_version(&self) -> u8 {
        self.inverse_version
    }

    /// Raw payload type as `u16`
    #[must_use]
    pub fn payload_type(&self) -> u16 {
        self.payload_type
    }

    /// Payload length in bytes
    #[must_use]
    pub fn payload_length(&self) -> u32 {
        self.payload_length
    }
}

impl Default for DoipHeader {
    fn default() -> Self {
        Self {
            version: DEFAULT_PROTOCOL_VERSION,
            inverse_version: DEFAULT_PROTOCOL_VERSION_INV,
            payload_type: 0,
            payload_length: 0,
        }
    }
}

impl std::fmt::Display for DoipHeader {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let payload_name = PayloadType::try_from(self.payload_type).ok().map_or_else(
            || format!("Unknown(0x{:04X})", self.payload_type),
            |pt| format!("{pt:?}"),
        );
        write!(
            f,
            "DoipHeader {{ version: 0x{:02X}, type: {}, length: {} }}",
            self.version, payload_name, self.payload_length
        )
    }
}

/// `DoIP` Message (ISO 13400-2 Section 6)
///
/// Complete `DoIP` message consisting of an 8-byte header and variable-length payload.
/// ISO 13400-2 uses the term "message" throughout the specification.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DoipMessage {
    pub(crate) header: DoipHeader,
    pub(crate) payload: Bytes,
}

impl DoipMessage {
    /// Create a new `DoIP` message with the default protocol version.
    #[cfg(test)]
    pub(crate) fn new(payload_type: PayloadType, payload: Bytes) -> Self {
        Self {
            header: DoipHeader {
                version: DEFAULT_PROTOCOL_VERSION,
                inverse_version: DEFAULT_PROTOCOL_VERSION_INV,
                payload_type: u16::from(payload_type),
                payload_length: u32::try_from(payload.len()).expect("test payload fits in u32"),
            },
            payload,
        }
    }

    /// Create a DoIP message with a raw (unparsed) payload type
    ///
    /// This is primarily used for testing unknown/invalid payload types.
    /// Production code should use `new()` or `with_version()` instead.
    #[cfg(test)]
    pub fn with_raw_payload_type(payload_type: u16, payload: Bytes) -> Self {
        Self {
            header: DoipHeader {
                version: DEFAULT_PROTOCOL_VERSION,
                inverse_version: DEFAULT_PROTOCOL_VERSION_INV,
                payload_type,
                payload_length: u32::try_from(payload.len()).expect("test payload fits in u32"),
            },
            payload,
        }
    }

    pub fn payload_type(&self) -> Option<PayloadType> {
        PayloadType::try_from(self.header.payload_type).ok()
    }

    /// The `DoIP` header
    pub fn header(&self) -> &DoipHeader {
        &self.header
    }

    /// The message payload bytes
    pub fn payload(&self) -> &Bytes {
        &self.payload
    }

    /// Returns the total message length (header + payload)
    #[must_use]
    pub fn message_length(&self) -> usize {
        DOIP_HEADER_LENGTH.saturating_add(self.payload.len())
    }

    pub fn to_bytes(&self) -> Bytes {
        let mut buf = BytesMut::with_capacity(self.message_length());
        self.header.write_to(&mut buf);
        buf.extend_from_slice(&self.payload);
        buf.freeze()
    }
}

// ============================================================================
// Unit Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use crate::doip::codec::DoipCodec;
    use tokio_util::codec::{Decoder, Encoder};

    // --- Helper to build a valid DoIP header quickly ---
    fn make_header(payload_type: u16, payload_len: u32) -> DoipHeader {
        DoipHeader {
            version: 0x02,
            inverse_version: 0xFD,
            payload_type,
            payload_length: payload_len,
        }
    }

    // -------------------------------------------------------------------------
    // Basic header parsing - the bread and butter
    // -------------------------------------------------------------------------

    #[test]
    fn parse_vehicle_id_request_from_tester() {
        // Real-world: tester broadcasts "who's there?" on UDP
        let raw = [0x02, 0xFD, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00];
        let hdr = DoipHeader::parse(&raw).unwrap();

        assert_eq!(hdr.payload_type, 0x0001);
        assert_eq!(hdr.payload_length, 0);
        assert!(hdr.is_valid());
    }

    #[test]
    fn parse_diagnostic_message_with_uds_payload() {
        // Tester sends UDS request: SA=0x0E80, TA=0x1001, SID=0x22 (ReadDataByID)
        let raw = [0x02, 0xFD, 0x80, 0x01, 0x00, 0x00, 0x00, 0x07];
        let hdr = DoipHeader::parse(&raw).unwrap();

        assert_eq!(hdr.payload_type, 0x8001); // DiagnosticMessage
        assert_eq!(hdr.payload_length, 7); // 2+2+3 = SA+TA+UDS
    }

    #[test]
    fn parse_routing_activation_request() {
        // Tester wants to start a diagnostic session
        let raw = [0x02, 0xFD, 0x00, 0x05, 0x00, 0x00, 0x00, 0x07];
        let hdr = DoipHeader::parse(&raw).unwrap();

        assert_eq!(hdr.payload_type, 0x0005);
        assert!(hdr.is_valid());
    }

    #[test]
    fn reject_truncated_header() {
        // Only 4 bytes arrived - not enough
        let partial = [0x02, 0xFD, 0x00, 0x01];
        assert!(DoipHeader::parse(&partial).is_err());
    }

    #[test]
    fn extra_bytes_after_header_are_ignored() {
        // Header + some payload bytes mixed in
        let raw = [0x02, 0xFD, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0xDE, 0xAD];
        let hdr = DoipHeader::parse(&raw).unwrap();
        assert_eq!(hdr.payload_length, 0); // Parses only header
    }

    // -------------------------------------------------------------------------
    // Validation - reject bad packets before processing
    // -------------------------------------------------------------------------

    #[test]
    fn reject_wrong_protocol_version() {
        // Someone sends version 0x04 - we only support 0x01, 0x02, 0x03, 0xFF
        let hdr = DoipHeader {
            version: 0x04,
            inverse_version: 0xFB,
            payload_type: 0x0001,
            payload_length: 0,
        };
        assert_eq!(
            hdr.validate(),
            Some(GenericNackCode::IncorrectPatternFormat)
        );
    }

    #[test]
    fn reject_corrupted_inverse_version() {
        // Inverse should be 0xFD for version 0x02, but we got 0xFC
        let hdr = DoipHeader {
            version: 0x02,
            inverse_version: 0xFC, // Wrong!
            payload_type: 0x0001,
            payload_length: 0,
        };
        assert_eq!(
            hdr.validate(),
            Some(GenericNackCode::IncorrectPatternFormat)
        );
    }

    #[test]
    fn reject_unknown_payload_type() {
        // 0x1234 is not a valid DoIP payload type
        let hdr = make_header(0x1234, 0);
        assert_eq!(hdr.validate(), Some(GenericNackCode::UnknownPayloadType));
    }

    #[test]
    fn reject_oversized_message() {
        // Payload claims to be 256MB - way too big
        let hdr = make_header(0x8001, MAX_DOIP_MESSAGE_SIZE + 1);
        assert_eq!(hdr.validate(), Some(GenericNackCode::MessageTooLarge));
    }

    #[test]
    fn reject_diagnostic_msg_with_too_small_payload() {
        // DiagnosticMessage needs at least 5 bytes (SA + TA + 1 UDS byte)
        let hdr = make_header(0x8001, 3);
        assert_eq!(hdr.validate(), Some(GenericNackCode::InvalidPayloadLength));
    }

    #[test]
    fn accept_max_allowed_payload_size() {
        let hdr = make_header(0x8001, MAX_DOIP_MESSAGE_SIZE);
        assert!(hdr.is_valid());
    }

    // -------------------------------------------------------------------------
    // PayloadType enum - mapping values correctly
    // -------------------------------------------------------------------------

    #[test]
    fn payload_type_lookup_works() {
        assert_eq!(
            PayloadType::try_from(0x0001).ok(),
            Some(PayloadType::VehicleIdentificationRequest)
        );
        assert_eq!(
            PayloadType::try_from(0x0005).ok(),
            Some(PayloadType::RoutingActivationRequest)
        );
        assert_eq!(
            PayloadType::try_from(0x8001).ok(),
            Some(PayloadType::DiagnosticMessage)
        );
        assert_eq!(
            PayloadType::try_from(0x8002).ok(),
            Some(PayloadType::DiagnosticMessagePositiveAck)
        );
    }

    #[test]
    fn payload_type_gaps_return_none() {
        // These are in gaps between valid ranges
        assert!(PayloadType::try_from(0x0009_u16).is_err());
        assert!(PayloadType::try_from(0x4000_u16).is_err());
        assert!(PayloadType::try_from(0x8000_u16).is_err());
        assert!(PayloadType::try_from(0xFFFF_u16).is_err());
    }

    #[test]
    fn minimum_payload_lengths_per_spec() {
        // ISO 13400-2 requirements
        assert_eq!(
            PayloadType::VehicleIdentificationRequest.min_payload_length(),
            0
        );
        assert_eq!(
            PayloadType::RoutingActivationRequest.min_payload_length(),
            7
        );
        assert_eq!(PayloadType::DiagnosticMessage.min_payload_length(), 5);
        assert_eq!(PayloadType::AliveCheckResponse.min_payload_length(), 2);
    }

    // -------------------------------------------------------------------------
    // DoipMessage - wrapping header + payload together
    // -------------------------------------------------------------------------

    #[test]
    fn create_tester_present_message() {
        // UDS TesterPresent: 0x3E 0x00
        let uds = Bytes::from_static(&[0x0E, 0x80, 0x10, 0x01, 0x3E, 0x00]);
        let msg = DoipMessage::new(PayloadType::DiagnosticMessage, uds);

        assert_eq!(msg.header.payload_type, 0x8001);
        assert_eq!(msg.header.payload_length, 6);
        assert_eq!(msg.payload_type(), Some(PayloadType::DiagnosticMessage));
    }

    #[test]
    fn create_vehicle_id_broadcast() {
        // Empty payload for discovery
        let msg = DoipMessage::new(PayloadType::VehicleIdentificationRequest, Bytes::new());

        assert_eq!(msg.header.payload_length, 0);
        assert_eq!(msg.message_length(), 8); // Just the header
    }

    #[test]
    fn message_with_unknown_type() {
        // For testing/fuzzing - create msg with invalid type
        let msg = DoipMessage::with_raw_payload_type(0xBEEF, Bytes::new());
        assert_eq!(msg.payload_type(), None);
    }

    #[test]
    fn serialize_message_to_wire_format() {
        let msg = DoipMessage::new(PayloadType::AliveCheckRequest, Bytes::new());
        let wire = msg.to_bytes();

        assert_eq!(wire.len(), 8);
        assert_eq!(&wire[..4], &[0x02, 0xFD, 0x00, 0x07]); // Version + type
        assert_eq!(&wire[4..8], &[0x00, 0x00, 0x00, 0x00]); // Length = 0
    }

    // -------------------------------------------------------------------------
    // Codec - TCP stream framing
    // -------------------------------------------------------------------------

    #[test]
    fn decode_complete_alive_check_response() {
        let mut codec = DoipCodec::new();
        // AliveCheckResponse with source address 0x0E80
        let mut buf =
            BytesMut::from(&[0x02, 0xFD, 0x00, 0x08, 0x00, 0x00, 0x00, 0x02, 0x0E, 0x80][..]);

        let msg = codec.decode(&mut buf).unwrap().unwrap();
        assert_eq!(msg.header.payload_type, 0x0008);
        assert_eq!(msg.payload.as_ref(), &[0x0E, 0x80]);
        assert!(buf.is_empty()); // Consumed everything
    }

    #[test]
    fn wait_for_more_data_when_header_incomplete() {
        let mut codec = DoipCodec::new();
        let mut buf = BytesMut::from(&[0x02, 0xFD, 0x00][..]); // Only 3 bytes

        assert!(codec.decode(&mut buf).unwrap().is_none());
        assert_eq!(buf.len(), 3); // Nothing consumed
    }

    #[test]
    fn wait_for_more_data_when_payload_incomplete() {
        let mut codec = DoipCodec::new();
        // Header says 5 bytes payload, but only 2 arrived
        let mut buf =
            BytesMut::from(&[0x02, 0xFD, 0x80, 0x01, 0x00, 0x00, 0x00, 0x05, 0x0E, 0x80][..]);

        assert!(codec.decode(&mut buf).unwrap().is_none());
    }

    #[test]
    fn decode_back_to_back_messages() {
        let mut codec = DoipCodec::new();
        let mut buf = BytesMut::from(
            &[
                // Msg 1: AliveCheckRequest
                0x02, 0xFD, 0x00, 0x07, 0x00, 0x00, 0x00, 0x00,
                // Msg 2: AliveCheckResponse
                0x02, 0xFD, 0x00, 0x08, 0x00, 0x00, 0x00, 0x02, 0x0E, 0x80,
            ][..],
        );

        let m1 = codec.decode(&mut buf).unwrap().unwrap();
        let m2 = codec.decode(&mut buf).unwrap().unwrap();

        assert_eq!(m1.header.payload_type, 0x0007);
        assert_eq!(m2.header.payload_type, 0x0008);
        assert!(buf.is_empty());
    }

    #[test]
    fn reject_invalid_header_in_stream() {
        let mut codec = DoipCodec::new();
        // Bad version (0x04 is not valid - only 0x01, 0x02, 0x03, 0xFF are accepted)
        let mut buf = BytesMut::from(&[0x04, 0xFB, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00][..]);

        assert!(codec.decode(&mut buf).is_err());
    }

    #[test]
    fn respect_custom_max_payload_size() {
        let mut codec = DoipCodec::with_max_payload_size(100);
        // Payload length = 101, over our limit
        let mut buf = BytesMut::from(&[0x02, 0xFD, 0x80, 0x01, 0x00, 0x00, 0x00, 0x65][..]);

        assert!(codec.decode(&mut buf).is_err());
    }

    #[test]
    fn encode_diagnostic_message() {
        let mut codec = DoipCodec::new();
        let payload = Bytes::from_static(&[0x0E, 0x80, 0x10, 0x01, 0x3E]);
        let msg = DoipMessage::new(PayloadType::DiagnosticMessage, payload);

        let mut buf = BytesMut::new();
        codec.encode(msg, &mut buf).unwrap();

        assert_eq!(&buf[..4], &[0x02, 0xFD, 0x80, 0x01]);
        assert_eq!(&buf[4..8], &[0x00, 0x00, 0x00, 0x05]);
        assert_eq!(&buf[8..], &[0x0E, 0x80, 0x10, 0x01, 0x3E]);
    }

    // -------------------------------------------------------------------------
    // Round-trip: encode then decode should give same data
    // -------------------------------------------------------------------------

    #[test]
    fn roundtrip_diagnostic_message() {
        let mut codec = DoipCodec::new();
        let original = DoipMessage::new(
            PayloadType::DiagnosticMessage,
            Bytes::from_static(&[0x0E, 0x80, 0x10, 0x01, 0x22, 0xF1, 0x90]),
        );

        let mut buf = BytesMut::new();
        codec.encode(original.clone(), &mut buf).unwrap();
        let decoded = codec.decode(&mut buf).unwrap().unwrap();

        assert_eq!(original.header, decoded.header);
        assert_eq!(original.payload, decoded.payload);
    }

    #[test]
    fn roundtrip_header_only() {
        let original = make_header(0x8001, 42);
        let bytes = original.to_bytes();
        let parsed = DoipHeader::parse(&bytes).unwrap();

        assert_eq!(original, parsed);
    }

    // -------------------------------------------------------------------------
    // Edge cases and error handling
    // -------------------------------------------------------------------------

    #[test]
    fn handle_all_zeros_gracefully() {
        let garbage = [0x00; 8];
        let hdr = DoipHeader::parse(&garbage).unwrap();
        assert!(!hdr.is_valid()); // Wrong version, but doesn't panic
    }

    #[test]
    fn handle_all_ones_gracefully() {
        let garbage = [0xFF; 8];
        let hdr = DoipHeader::parse(&garbage).unwrap();
        assert!(!hdr.is_valid());
    }

    #[test]
    fn parse_error_shows_useful_message() {
        let result = DoipHeader::parse(&[]);
        let msg = format!("{}", result.unwrap_err());
        assert!(msg.contains("DoIP header"));
    }

    #[test]
    fn nack_codes_have_correct_values() {
        // Per ISO 13400-2 Table 17
        assert_eq!(GenericNackCode::IncorrectPatternFormat as u8, 0x00);
        assert_eq!(GenericNackCode::UnknownPayloadType as u8, 0x01);
        assert_eq!(GenericNackCode::MessageTooLarge as u8, 0x02);
        assert_eq!(GenericNackCode::OutOfMemory as u8, 0x03);
        assert_eq!(GenericNackCode::InvalidPayloadLength as u8, 0x04);
    }

    #[test]
    fn protocol_version_inverse_relationship() {
        // Version XOR inverse must equal DOIP_HEADER_VERSION_MASK (0xFF, per ISO 13400-2:2019 spec)
        assert_eq!(
            DEFAULT_PROTOCOL_VERSION ^ DEFAULT_PROTOCOL_VERSION_INV,
            DOIP_HEADER_VERSION_MASK
        );
    }

    #[test]
    fn header_display_shows_readable_info() {
        let hdr = make_header(0x8001, 10);
        let s = format!("{hdr}");
        assert!(s.contains("DiagnosticMessage"));
        assert!(s.contains("10")); // payload length
    }

    #[test]
    fn default_header_has_correct_version() {
        let hdr = DoipHeader::default();
        assert_eq!(hdr.version, 0x02);
        assert_eq!(hdr.inverse_version, 0xFD);
    }
}
