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

use bytes::{BufMut, Bytes, BytesMut};
use tracing::error;

use super::{DoipParseable, DoipSerializable, parse_fixed_slice, too_short};
use crate::{DoipError, Result};

const ADDRESS_BYTES: usize = 2;
const HEADER_BYTES: usize = ADDRESS_BYTES * 2;
const ACK_CODE_BYTES: usize = 1;
const MIN_USER_DATA_BYTES: usize = 1;
/// Wire code for a positive diagnostic acknowledgment (ISO 13400-2:2019 Table 27).
const POSITIVE_ACK_CODE: u8 = 0x00;

/// Parse source and target addresses from a 4-byte address-pair header.
/// Layout: SA(2 bytes, big-endian) + TA(2 bytes, big-endian).
fn parse_address_pair(header: [u8; HEADER_BYTES]) -> (u16, u16) {
    let source = u16::from_be_bytes([header[0], header[1]]);
    let target = u16::from_be_bytes([header[2], header[3]]);
    (source, target)
}

/// Outcome of a diagnostic message acknowledgment (ISO 13400-2:2019).
///
/// Used by [`DiagnosticAck`] to represent either a positive or negative result.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AckResult {
    /// Positive acknowledgment — message was accepted (wire code 0x00).
    Positive,
    /// Negative acknowledgment — message was rejected with the given code.
    Negative(DiagnosticNackCode),
}

/// Diagnostic message negative acknowledgment codes per ISO 13400-2:2019 Table 28.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum DiagnosticNackCode {
    InvalidSourceAddress = 0x02,
    UnknownTargetAddress = 0x03,
    DiagnosticMessageTooLarge = 0x04,
    OutOfMemory = 0x05,
    TargetUnreachable = 0x06,
    UnknownNetwork = 0x07,
    TransportProtocolError = 0x08,
}

impl TryFrom<u8> for DiagnosticNackCode {
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

impl From<DiagnosticNackCode> for u8 {
    fn from(code: DiagnosticNackCode) -> Self {
        code as Self
    }
}

/// Diagnostic Message - carries UDS data between tester and ECU
///
/// Represents a `DoIP` diagnostic message as defined in ISO 13400-2:2019.
/// The message contains source/target addresses and UDS payload data.
///
/// # Wire Format
/// Payload: SA(2) + TA(2) + `user_data(1`+)
///
/// `Clone` is derived because [`DoipPayload`](super::payload::DoipPayload) wraps this type and itself derives `Clone`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DiagnosticMessage {
    source_address: u16,
    target_address: u16,
    user_data: Bytes,
}

impl DiagnosticMessage {
    /// Minimum message length in bytes (SA + TA + at least 1 byte UDS data)
    pub(crate) const MIN_LEN: usize = HEADER_BYTES + MIN_USER_DATA_BYTES;

    /// Create a new diagnostic message.
    ///
    /// # Arguments
    /// * `source` - Source address (tester or ECU)
    /// * `target` - Target address (tester or ECU)
    /// * `data` - UDS payload data (must not be empty)
    ///
    /// # Errors
    /// Returns [`DoipError::EmptyUserData`] if `data` is empty.
    pub fn new(source: u16, target: u16, data: Bytes) -> Result<Self> {
        if data.is_empty() {
            return Err(DoipError::EmptyUserData);
        }
        Ok(Self {
            source_address: source,
            target_address: target,
            user_data: data,
        })
    }

    /// Get the source address
    #[must_use]
    pub fn source_address(&self) -> u16 {
        self.source_address
    }

    /// Get the target address
    #[must_use]
    pub fn target_address(&self) -> u16 {
        self.target_address
    }

    /// Get the UDS user data
    #[must_use]
    pub fn user_data(&self) -> &Bytes {
        &self.user_data
    }

    /// Returns the UDS service ID (first byte of user data), or `None` if the payload is empty.
    #[must_use]
    pub fn service_id(&self) -> Option<u8> {
        self.user_data.first().copied()
    }
}

/// Diagnostic Message Acknowledgment (payload types 0x8002 and 0x8003)
///
/// Represents both positive and negative acknowledgments as defined in
/// ISO 13400-2:2019. Use [`AckResult`] to distinguish the outcome.
///
/// # Wire Format
/// Payload: SA(2) + TA(2) + code(1) + optional `previous_diag_data`
#[derive(Debug, PartialEq, Eq)]
pub struct DiagnosticAck {
    source_address: u16,
    target_address: u16,
    result: AckResult,
    previous_data: Option<Bytes>,
}

impl DiagnosticAck {
    /// Minimum ack length in bytes (SA + TA + code byte).
    pub(crate) const MIN_LEN: usize = HEADER_BYTES + ACK_CODE_BYTES;

    /// Create a positive acknowledgment.
    #[must_use]
    pub fn positive(source: u16, target: u16) -> Self {
        Self {
            source_address: source,
            target_address: target,
            result: AckResult::Positive,
            previous_data: None,
        }
    }

    /// Create a negative acknowledgment.
    #[must_use]
    pub fn negative(source: u16, target: u16, code: DiagnosticNackCode) -> Self {
        Self {
            source_address: source,
            target_address: target,
            result: AckResult::Negative(code),
            previous_data: None,
        }
    }

    /// Returns the source address.
    #[must_use]
    pub fn source_address(&self) -> u16 {
        self.source_address
    }

    /// Returns the target address.
    #[must_use]
    pub fn target_address(&self) -> u16 {
        self.target_address
    }

    /// Returns the acknowledgment result.
    #[must_use]
    pub fn result(&self) -> AckResult {
        self.result
    }

    /// Returns the previous diagnostic data, if any.
    #[must_use]
    pub fn previous_data(&self) -> Option<&Bytes> {
        self.previous_data.as_ref()
    }

    /// Parse a positive acknowledgment payload (payload type 0x8002).
    ///
    /// # Errors
    /// Returns [`DoipError::PayloadTooShort`] if payload is less than 4 bytes.
    pub(crate) fn parse_positive(payload: &[u8]) -> Result<Self> {
        let (source_address, target_address, previous_data) =
            Self::parse_address_header(payload, "DiagnosticPositiveAck")?;
        Ok(Self {
            source_address,
            target_address,
            result: AckResult::Positive,
            previous_data,
        })
    }

    /// Parse a negative acknowledgment payload (payload type 0x8003).
    ///
    /// # Errors
    /// Returns [`DoipError::PayloadTooShort`] if payload is less than 5 bytes.
    /// Returns [`DoipError::UnknownNackCode`] for unrecognized NACK codes.
    pub(crate) fn parse_negative(payload: &[u8]) -> Result<Self> {
        let (source_address, target_address, previous_data) =
            Self::parse_address_header(payload, "DiagnosticNegativeAck")?;
        let nack_code = payload
            .get(HEADER_BYTES)
            .copied()
            .ok_or_else(|| too_short(payload, Self::MIN_LEN))
            .and_then(DiagnosticNackCode::try_from)?;
        Ok(Self {
            source_address,
            target_address,
            result: AckResult::Negative(nack_code),
            previous_data,
        })
    }

    /// Parse SA, TA and optional trailing `previous_data` from an ack payload.
    fn parse_address_header(payload: &[u8], context: &str) -> Result<(u16, u16, Option<Bytes>)> {
        let header: [u8; HEADER_BYTES] = parse_fixed_slice(payload, context)?;
        let (source_address, target_address) = parse_address_pair(header);
        let previous_data = payload
            .get(Self::MIN_LEN..)
            .filter(|d| !d.is_empty())
            .map(Bytes::copy_from_slice);
        Ok((source_address, target_address, previous_data))
    }
}

impl DoipParseable for DiagnosticMessage {
    fn parse(payload: &[u8]) -> Result<Self> {
        let header: [u8; HEADER_BYTES] = parse_fixed_slice(payload, "DiagnosticMessage")?;

        let (source_address, target_address) = parse_address_pair(header);

        let user_data = payload
            .get(HEADER_BYTES..)
            .map(Bytes::copy_from_slice)
            .ok_or_else(|| {
                let e = too_short(payload, Self::MIN_LEN);
                error!(error = %e, "DiagnosticMessage parse failed");
                e
            })?;

        if user_data.is_empty() {
            error!(
                message_type = "DiagnosticMessage",
                reason = "empty_user_data",
                "parse failed"
            );
            return Err(DoipError::EmptyUserData);
        }

        Ok(Self {
            source_address,
            target_address,
            user_data,
        })
    }
}

impl DoipSerializable for DiagnosticMessage {
    fn serialized_len(&self) -> Option<usize> {
        Some(HEADER_BYTES.saturating_add(self.user_data.len()))
    }

    fn write_to(&self, buf: &mut BytesMut) {
        buf.put_u16(self.source_address);
        buf.put_u16(self.target_address);
        buf.extend_from_slice(&self.user_data);
    }
}

impl DoipSerializable for DiagnosticAck {
    fn serialized_len(&self) -> Option<usize> {
        Some(Self::MIN_LEN.saturating_add(self.previous_data.as_ref().map_or(0, bytes::Bytes::len)))
    }

    fn write_to(&self, buf: &mut BytesMut) {
        buf.put_u16(self.source_address);
        buf.put_u16(self.target_address);
        buf.put_u8(match self.result {
            AckResult::Positive => POSITIVE_ACK_CODE,
            AckResult::Negative(code) => u8::from(code),
        });
        if let Some(ref data) = self.previous_data {
            buf.extend_from_slice(data);
        }
    }
}

#[cfg(test)]
#[allow(clippy::indexing_slicing)]
mod tests {
    use super::*;
    use crate::doip::{DoipParseable, DoipSerializable};

    #[test]
    fn nack_code_values() {
        assert_eq!(DiagnosticNackCode::InvalidSourceAddress as u8, 0x02);
        assert_eq!(DiagnosticNackCode::UnknownTargetAddress as u8, 0x03);
        assert_eq!(DiagnosticNackCode::TargetUnreachable as u8, 0x06);
    }

    #[test]
    fn parse_diagnostic_message() {
        // SA=0x0E80, TA=0x1000, UDS=0x22 0xF1 0x90 (ReadDataByID)
        let payload = [0x0E, 0x80, 0x10, 0x00, 0x22, 0xF1, 0x90];
        let msg = DiagnosticMessage::parse(&payload).unwrap();

        assert_eq!(msg.source_address(), 0x0E80);
        assert_eq!(msg.target_address(), 0x1000);
        assert_eq!(msg.user_data().as_ref(), &[0x22, 0xF1, 0x90]);
        assert_eq!(msg.service_id(), Some(0x22));
    }

    #[test]
    fn parse_tester_present() {
        // TesterPresent service
        let payload = [0x0E, 0x80, 0x10, 0x00, 0x3E, 0x00];
        let msg = DiagnosticMessage::parse(&payload).unwrap();

        assert_eq!(msg.service_id(), Some(0x3E));
        assert_eq!(msg.user_data().len(), 2);
    }

    #[test]
    fn reject_short_message() {
        let short = [0x0E, 0x80, 0x10, 0x00]; // no user data
        assert!(DiagnosticMessage::parse(&short).is_err());
    }

    #[test]
    fn build_diagnostic_message() {
        let uds = Bytes::from_static(&[0x22, 0xF1, 0x90]);
        let msg = DiagnosticMessage::new(0x0E80, 0x1000, uds).unwrap();
        let bytes = msg.to_bytes();

        assert_eq!(&bytes[..ADDRESS_BYTES], &[0x0E, 0x80]);
        assert_eq!(&bytes[ADDRESS_BYTES..HEADER_BYTES], &[0x10, 0x00]);
        assert_eq!(&bytes[HEADER_BYTES..], &[0x22, 0xF1, 0x90]);
    }

    #[test]
    fn build_positive_ack() {
        let ack = DiagnosticAck::positive(0x1000, 0x0E80);
        let bytes = ack.to_bytes();

        assert_eq!(bytes.len(), DiagnosticAck::MIN_LEN);
        assert_eq!(&bytes[..ADDRESS_BYTES], &[0x10, 0x00]);
        assert_eq!(&bytes[ADDRESS_BYTES..HEADER_BYTES], &[0x0E, 0x80]);
        assert_eq!(bytes[HEADER_BYTES], 0x00); // positive ack wire code
        assert_eq!(ack.result(), AckResult::Positive);
    }

    #[test]
    fn build_negative_ack() {
        let nack =
            DiagnosticAck::negative(0x1000, 0x0E80, DiagnosticNackCode::UnknownTargetAddress);
        let bytes = nack.to_bytes();

        assert_eq!(bytes.len(), DiagnosticAck::MIN_LEN);
        assert_eq!(bytes[HEADER_BYTES], 0x03);
        assert_eq!(
            nack.result(),
            AckResult::Negative(DiagnosticNackCode::UnknownTargetAddress)
        );
    }

    #[test]
    fn build_negative_ack_target_unreachable() {
        let nack = DiagnosticAck::negative(0x1000, 0x0E80, DiagnosticNackCode::TargetUnreachable);
        let bytes = nack.to_bytes();
        assert_eq!(bytes[HEADER_BYTES], 0x06);
    }

    #[test]
    fn parse_positive_ack() {
        let payload = [0x10, 0x00, 0x0E, 0x80, 0x00];
        let ack = DiagnosticAck::parse_positive(&payload).unwrap();

        assert_eq!(ack.source_address(), 0x1000);
        assert_eq!(ack.target_address(), 0x0E80);
        assert_eq!(ack.result(), AckResult::Positive);
        assert!(ack.previous_data().is_none());
    }

    #[test]
    fn parse_negative_ack() {
        let payload = [0x10, 0x00, 0x0E, 0x80, 0x03];
        let nack = DiagnosticAck::parse_negative(&payload).unwrap();

        assert_eq!(
            nack.result(),
            AckResult::Negative(DiagnosticNackCode::UnknownTargetAddress)
        );
    }

    #[test]
    fn reject_empty_user_data() {
        let err = DiagnosticMessage::new(0x0E80, 0x1000, Bytes::new());
        assert!(matches!(err, Err(DoipError::EmptyUserData)));
    }

    #[test]
    fn roundtrip_message() {
        let original =
            DiagnosticMessage::new(0x0E80, 0x1000, Bytes::from_static(&[0x10, 0x01])).unwrap();
        let bytes = original.to_bytes();
        let parsed = DiagnosticMessage::parse(&bytes).unwrap();
        assert_eq!(original, parsed);
    }

    #[test]
    fn roundtrip_positive_ack() {
        let original = DiagnosticAck::positive(0x1000, 0x0E80);
        let bytes = original.to_bytes();
        let parsed = DiagnosticAck::parse_positive(&bytes).unwrap();
        assert_eq!(original, parsed);
    }

    #[test]
    fn roundtrip_negative_ack() {
        let original = DiagnosticAck::negative(0x1000, 0x0E80, DiagnosticNackCode::OutOfMemory);
        let bytes = original.to_bytes();
        let parsed = DiagnosticAck::parse_negative(&bytes).unwrap();
        assert_eq!(original, parsed);
    }
}
