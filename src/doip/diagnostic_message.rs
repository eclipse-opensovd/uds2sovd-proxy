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
//! Diagnostic Message handlers (ISO 13400-2:2019)

use super::{check_min_len, too_short, DoipParseable, DoipSerializable};
use crate::DoipError;
use bytes::{Buf, BufMut, Bytes, BytesMut};
use tracing::warn;

const ADDRESS_BYTES: usize = 2;
const HEADER_BYTES: usize = ADDRESS_BYTES * 2;
const ACK_CODE_BYTES: usize = 1;
const MIN_USER_DATA_BYTES: usize = 1;

// Diagnostic message positive ack codes per ISO 13400-2:2019 Table 27
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum AckCode {
    Acknowledged = 0x00,
}

// Diagnostic message negative ack codes per ISO 13400-2:2019 Table 28
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum NackCode {
    InvalidSourceAddress = 0x02,
    UnknownTargetAddress = 0x03,
    DiagnosticMessageTooLarge = 0x04,
    OutOfMemory = 0x05,
    TargetUnreachable = 0x06,
    UnknownNetwork = 0x07,
    TransportProtocolError = 0x08,
}

impl TryFrom<u8> for NackCode {
    type Error = DoipError;

    fn try_from(value: u8) -> std::result::Result<Self, Self::Error> {
        match value {
            0x02 => Ok(Self::InvalidSourceAddress),
            0x03 => Ok(Self::UnknownTargetAddress),
            0x04 => Ok(Self::DiagnosticMessageTooLarge),
            0x05 => Ok(Self::OutOfMemory),
            0x06 => Ok(Self::TargetUnreachable),
            0x07 => Ok(Self::UnknownNetwork),
            0x08 => Ok(Self::TransportProtocolError),
            other => Err(DoipError::UnknownNackCode(other)),
        }
    }
}

/// Diagnostic Message - carries UDS data between tester and ECU
///
/// Represents a DoIP diagnostic message as defined in ISO 13400-2:2019.
/// The message contains source/target addresses and UDS payload data.
///
/// # Wire Format
/// Payload: SA(2) + TA(2) + user_data(1+)
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Message {
    source_address: u16,
    target_address: u16,
    user_data: Bytes,
}

impl Message {
    /// Minimum message length in bytes (SA + TA + at least 1 byte UDS data)
    pub const MIN_LEN: usize = HEADER_BYTES + MIN_USER_DATA_BYTES;

    /// Create a new diagnostic message
    ///
    /// # Arguments
    /// * `source` - Source address (tester or ECU)
    /// * `target` - Target address (tester or ECU)
    /// * `data` - UDS payload data
    pub fn new(source: u16, target: u16, data: Bytes) -> Self {
        Self {
            source_address: source,
            target_address: target,
            user_data: data,
        }
    }

    /// Get the source address
    pub fn source_address(&self) -> u16 {
        self.source_address
    }

    /// Get the target address  
    pub fn target_address(&self) -> u16 {
        self.target_address
    }

    /// Get the UDS user data
    pub fn user_data(&self) -> &Bytes {
        &self.user_data
    }

    /// Parse a Diagnostic Message from a mutable Bytes buffer
    ///
    /// # Errors
    /// Returns [`DoipError::PayloadTooShort`] if buffer is less than 5 bytes
    /// Returns [`DoipError::EmptyUserData`] if no UDS data is present
    pub fn parse_buf(buf: &mut Bytes) -> std::result::Result<Self, DoipError> {
        let msg = <Self as DoipParseable>::parse(buf)?;
        buf.advance(buf.len());
        Ok(msg)
    }

    pub fn service_id(&self) -> Option<u8> {
        self.user_data.first().copied()
    }
}

/// Diagnostic Message Positive Acknowledgment (message type 0x8002)
///
/// Sent by a DoIP entity to acknowledge receipt of a diagnostic message.
///
/// # Wire Format  
/// Payload: SA(2) + TA(2) + ack_code(1) + optional previous_diag_data
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PositiveAck {
    source_address: u16,
    target_address: u16,
    ack_code: AckCode,
    previous_data: Option<Bytes>,
}

impl PositiveAck {
    /// Minimum positive ack length in bytes
    pub const MIN_LEN: usize = HEADER_BYTES + ACK_CODE_BYTES;

    /// Create a new positive acknowledgment
    pub fn new(source: u16, target: u16) -> Self {
        Self {
            source_address: source,
            target_address: target,
            ack_code: AckCode::Acknowledged,
            previous_data: None,
        }
    }

    /// Create a positive acknowledgment with previous diagnostic data
    pub fn with_previous_data(source: u16, target: u16, data: Bytes) -> Self {
        Self {
            source_address: source,
            target_address: target,
            ack_code: AckCode::Acknowledged,
            // ISO 13400-2:2019: previous diagnostic data is optional; treat empty as absent
            previous_data: if data.is_empty() { None } else { Some(data) },
        }
    }

    /// Get the source address
    pub fn source_address(&self) -> u16 {
        self.source_address
    }

    /// Get the target address
    pub fn target_address(&self) -> u16 {
        self.target_address
    }

    /// Get the acknowledgment code
    pub fn ack_code(&self) -> AckCode {
        self.ack_code
    }

    /// Get the previous diagnostic data
    pub fn previous_data(&self) -> Option<&Bytes> {
        self.previous_data.as_ref()
    }
}

/// Diagnostic Message Negative Acknowledgment (message type 0x8003)
///
/// Sent by a DoIP entity to indicate rejection of a diagnostic message.
/// NACK codes are defined in ISO 13400-2:2019 Table 28.
///
/// # Wire Format
/// Payload: SA(2) + TA(2) + nack_code(1) + optional previous_diag_data
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NegativeAck {
    source_address: u16,
    target_address: u16,
    nack_code: NackCode,
    previous_data: Option<Bytes>,
}

impl NegativeAck {
    /// Minimum negative ack length in bytes
    pub const MIN_LEN: usize = HEADER_BYTES + ACK_CODE_BYTES;

    /// Create a new negative acknowledgment
    pub fn new(source: u16, target: u16, code: NackCode) -> Self {
        Self {
            source_address: source,
            target_address: target,
            nack_code: code,
            previous_data: None,
        }
    }

    /// Get the source address
    pub fn source_address(&self) -> u16 {
        self.source_address
    }

    /// Get the target address
    pub fn target_address(&self) -> u16 {
        self.target_address
    }

    /// Get the negative acknowledgment code
    pub fn nack_code(&self) -> NackCode {
        self.nack_code
    }

    /// Get the previous diagnostic data
    pub fn previous_data(&self) -> Option<&Bytes> {
        self.previous_data.as_ref()
    }

    /// Create a negative acknowledgment with previous diagnostic data
    pub fn with_previous_data(source: u16, target: u16, code: NackCode, data: Bytes) -> Self {
        Self {
            source_address: source,
            target_address: target,
            nack_code: code,
            // ISO 13400-2:2019: previous diagnostic data is optional; treat empty as absent
            previous_data: if data.is_empty() { None } else { Some(data) },
        }
    }
}

impl DoipParseable for Message {
    fn parse(payload: &[u8]) -> std::result::Result<Self, DoipError> {
        let header: [u8; HEADER_BYTES] = payload
            .get(..HEADER_BYTES)
            .and_then(|s| s.try_into().ok())
            .ok_or_else(|| {
                let e = too_short(payload, Self::MIN_LEN);
                warn!("DiagnosticMessage parse failed: {}", e);
                e
            })?;

        let source_address = u16::from_be_bytes([header[0], header[1]]);
        let target_address = u16::from_be_bytes([header[2], header[3]]);

        let user_data = payload
            .get(HEADER_BYTES..)
            .map(Bytes::copy_from_slice)
            .ok_or_else(|| {
                let e = too_short(payload, Self::MIN_LEN);
                warn!("DiagnosticMessage parse failed: {}", e);
                e
            })?;

        if user_data.is_empty() {
            warn!("DiagnosticMessage parse failed: empty user data");
            return Err(DoipError::EmptyUserData);
        }

        Ok(Self {
            source_address,
            target_address,
            user_data,
        })
    }
}

impl DoipSerializable for Message {
    fn serialized_len(&self) -> Option<usize> {
        Some(HEADER_BYTES + self.user_data.len())
    }

    fn write_to(&self, buf: &mut BytesMut) {
        buf.put_u16(self.source_address);
        buf.put_u16(self.target_address);
        buf.extend_from_slice(&self.user_data);
    }
}

impl DoipParseable for PositiveAck {
    fn parse(payload: &[u8]) -> std::result::Result<Self, DoipError> {
        if let Err(e) = check_min_len(payload, Self::MIN_LEN) {
            warn!("DiagnosticPositiveAck parse failed: {}", e);
            return Err(e);
        }

        let header: [u8; HEADER_BYTES] = payload
            .get(..HEADER_BYTES)
            .and_then(|s| s.try_into().ok())
            .ok_or_else(|| too_short(payload, Self::MIN_LEN))?;

        let source_address = u16::from_be_bytes([header[0], header[1]]);
        let target_address = u16::from_be_bytes([header[2], header[3]]);
        let ack_code = AckCode::Acknowledged;

        let previous_data = payload
            .get(Self::MIN_LEN..)
            .filter(|d| !d.is_empty())
            .map(Bytes::copy_from_slice);

        Ok(Self {
            source_address,
            target_address,
            ack_code,
            previous_data,
        })
    }
}

impl DoipSerializable for PositiveAck {
    fn serialized_len(&self) -> Option<usize> {
        Some(Self::MIN_LEN + self.previous_data.as_ref().map_or(0, |d| d.len()))
    }

    fn write_to(&self, buf: &mut BytesMut) {
        buf.put_u16(self.source_address);
        buf.put_u16(self.target_address);
        buf.put_u8(self.ack_code as u8);
        if let Some(ref data) = self.previous_data {
            buf.extend_from_slice(data);
        }
    }
}

impl DoipParseable for NegativeAck {
    fn parse(payload: &[u8]) -> std::result::Result<Self, DoipError> {
        if let Err(e) = check_min_len(payload, Self::MIN_LEN) {
            warn!("DiagnosticNegativeAck parse failed: {}", e);
            return Err(e);
        }

        let header: [u8; HEADER_BYTES] = payload
            .get(..HEADER_BYTES)
            .and_then(|s| s.try_into().ok())
            .ok_or_else(|| too_short(payload, Self::MIN_LEN))?;

        let source_address = u16::from_be_bytes([header[0], header[1]]);
        let target_address = u16::from_be_bytes([header[2], header[3]]);
        let nack_code = payload
            .get(HEADER_BYTES)
            .copied()
            .and_then(|b| NackCode::try_from(b).ok())
            .unwrap_or(NackCode::TransportProtocolError);

        let previous_data = payload
            .get(Self::MIN_LEN..)
            .filter(|d| !d.is_empty())
            .map(Bytes::copy_from_slice);

        Ok(Self {
            source_address,
            target_address,
            nack_code,
            previous_data,
        })
    }
}

impl DoipSerializable for NegativeAck {
    fn serialized_len(&self) -> Option<usize> {
        Some(Self::MIN_LEN + self.previous_data.as_ref().map_or(0, |d| d.len()))
    }

    fn write_to(&self, buf: &mut BytesMut) {
        buf.put_u16(self.source_address);
        buf.put_u16(self.target_address);
        buf.put_u8(self.nack_code as u8);
        if let Some(ref data) = self.previous_data {
            buf.extend_from_slice(data);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::doip::{DoipParseable, DoipSerializable};

    #[test]
    fn nack_code_values() {
        assert_eq!(NackCode::InvalidSourceAddress as u8, 0x02);
        assert_eq!(NackCode::UnknownTargetAddress as u8, 0x03);
        assert_eq!(NackCode::TargetUnreachable as u8, 0x06);
    }

    #[test]
    fn parse_diagnostic_message() {
        // SA=0x0E80, TA=0x1000, UDS=0x22 0xF1 0x90 (ReadDataByID)
        let payload = [0x0E, 0x80, 0x10, 0x00, 0x22, 0xF1, 0x90];
        let msg = Message::parse(&payload).unwrap();

        assert_eq!(msg.source_address(), 0x0E80);
        assert_eq!(msg.target_address(), 0x1000);
        assert_eq!(msg.user_data().as_ref(), &[0x22, 0xF1, 0x90]);
        assert_eq!(msg.service_id(), Some(0x22));
    }

    #[test]
    fn parse_tester_present() {
        // TesterPresent service
        let payload = [0x0E, 0x80, 0x10, 0x00, 0x3E, 0x00];
        let msg = Message::parse(&payload).unwrap();

        assert_eq!(msg.service_id(), Some(0x3E));
        assert_eq!(msg.user_data().len(), 2);
    }

    #[test]
    fn reject_short_message() {
        let short = [0x0E, 0x80, 0x10, 0x00]; // no user data
        assert!(Message::parse(&short).is_err());
    }

    #[test]
    fn build_diagnostic_message() {
        let uds = Bytes::from_static(&[0x22, 0xF1, 0x90]);
        let msg = Message::new(0x0E80, 0x1000, uds);
        let bytes = msg.to_bytes();

        assert_eq!(&bytes[..ADDRESS_BYTES], &[0x0E, 0x80]);
        assert_eq!(&bytes[ADDRESS_BYTES..HEADER_BYTES], &[0x10, 0x00]);
        assert_eq!(&bytes[HEADER_BYTES..], &[0x22, 0xF1, 0x90]);
    }

    #[test]
    fn build_positive_ack() {
        let ack = PositiveAck::new(0x1000, 0x0E80);
        let bytes = ack.to_bytes();

        assert_eq!(bytes.len(), PositiveAck::MIN_LEN);
        assert_eq!(&bytes[..ADDRESS_BYTES], &[0x10, 0x00]); // source (ECU)
        assert_eq!(&bytes[ADDRESS_BYTES..HEADER_BYTES], &[0x0E, 0x80]); // target (tester)
        assert_eq!(bytes[HEADER_BYTES], 0x00); // ack code
    }

    #[test]
    fn build_positive_ack_with_prev_data() {
        let prev = Bytes::from_static(&[0x22, 0xF1, 0x90]);
        let expected_len = PositiveAck::MIN_LEN + prev.len();
        let ack = PositiveAck::with_previous_data(0x1000, 0x0E80, prev);
        let bytes = ack.to_bytes();

        assert_eq!(bytes.len(), expected_len);
        assert_eq!(&bytes[PositiveAck::MIN_LEN..], &[0x22, 0xF1, 0x90]);
    }

    #[test]
    fn build_negative_ack() {
        let nack = NegativeAck::new(0x1000, 0x0E80, NackCode::UnknownTargetAddress);
        let bytes = nack.to_bytes();

        assert_eq!(bytes.len(), NegativeAck::MIN_LEN);
        assert_eq!(bytes[HEADER_BYTES], 0x03);
    }

    #[test]
    fn build_negative_ack_target_unreachable() {
        let nack = NegativeAck::new(0x1000, 0x0E80, NackCode::TargetUnreachable);
        let bytes = nack.to_bytes();
        assert_eq!(bytes[HEADER_BYTES], 0x06);
    }

    #[test]
    fn parse_positive_ack() {
        let payload = [0x10, 0x00, 0x0E, 0x80, 0x00];
        let ack = PositiveAck::parse(&payload).unwrap();

        assert_eq!(ack.source_address(), 0x1000);
        assert_eq!(ack.target_address(), 0x0E80);
        assert!(ack.previous_data().is_none());
    }

    #[test]
    fn parse_negative_ack() {
        let payload = [0x10, 0x00, 0x0E, 0x80, 0x03];
        let nack = NegativeAck::parse(&payload).unwrap();

        assert_eq!(nack.nack_code(), NackCode::UnknownTargetAddress);
    }

    #[test]
    fn roundtrip_message() {
        let original = Message::new(0x0E80, 0x1000, Bytes::from_static(&[0x10, 0x01]));
        let bytes = original.to_bytes();
        let parsed = Message::parse(&bytes).unwrap();
        assert_eq!(original, parsed);
    }

    #[test]
    fn roundtrip_positive_ack() {
        let original = PositiveAck::new(0x1000, 0x0E80);
        let bytes = original.to_bytes();
        let parsed = PositiveAck::parse(&bytes).unwrap();
        assert_eq!(original, parsed);
    }

    #[test]
    fn roundtrip_negative_ack() {
        let original = NegativeAck::new(0x1000, 0x0E80, NackCode::OutOfMemory);
        let bytes = original.to_bytes();
        let parsed = NegativeAck::parse(&bytes).unwrap();
        assert_eq!(original, parsed);
    }
}
