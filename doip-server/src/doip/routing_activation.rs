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
//! Routing Activation handlers (ISO 13400-2:2019)

use std::mem::size_of;

use bytes::{BufMut, BytesMut};
use tracing::error;

use super::{DoipParseable, DoipSerializable, parse_fixed_slice};
use crate::DoipError;
use crate::Result;

/// Byte length of the optional OEM-specific field (a single u32, big-endian).
const OEM_DATA_LEN: usize = size_of::<u32>();

/// Parse the optional 4-byte OEM-specific field from the end of a routing activation payload.
/// Returns `Some(u32)` when exactly `OEM_DATA_LEN` bytes are present beyond `min_len`,
/// and `None` when the payload ends at `min_len` (i.e. no OEM data).
fn parse_oem_specific(payload: &[u8], min_len: usize, max_len: usize) -> Option<u32> {
    payload
        .get(min_len..max_len)
        .and_then(|s| <[u8; OEM_DATA_LEN]>::try_from(s).ok())
        .map(u32::from_be_bytes)
}

/// Routing activation response codes per ISO 13400-2:2019 Table 25.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum ActivationResponseCode {
    /// Source address unknown to the `DoIP` entity (`0x00`)
    UnknownSourceAddress = 0x00,
    /// All TCP sockets on the `DoIP` entity are registered and active (`0x01`)
    AllSocketsRegistered = 0x01,
    /// Source address differs from the one registered to the socket (`0x02`)
    DifferentSourceAddress = 0x02,
    /// Source address is already registered on a different socket (`0x03`)
    SourceAddressAlreadyActive = 0x03,
    /// Routing activation denied; authentication required (`0x04`)
    MissingAuthentication = 0x04,
    /// Routing activation denied; confirmation rejected (`0x05`)
    RejectedConfirmation = 0x05,
    /// Unsupported routing activation type requested (`0x06`)
    UnsupportedActivationType = 0x06,
    /// TLS connection required before routing can be activated (`0x07`)
    TlsRequired = 0x07,
    /// Routing successfully activated (`0x10`)
    SuccessfullyActivated = 0x10,
    /// Routing activation pending; confirmation required (`0x11`)
    ConfirmationRequired = 0x11,
}

impl TryFrom<u8> for ActivationResponseCode {
    type Error = DoipError;

    fn try_from(value: u8) -> std::result::Result<Self, Self::Error> {
        match value {
            0x00 => Ok(Self::UnknownSourceAddress),
            0x01 => Ok(Self::AllSocketsRegistered),
            0x02 => Ok(Self::DifferentSourceAddress),
            0x03 => Ok(Self::SourceAddressAlreadyActive),
            0x04 => Ok(Self::MissingAuthentication),
            0x05 => Ok(Self::RejectedConfirmation),
            0x06 => Ok(Self::UnsupportedActivationType),
            0x07 => Ok(Self::TlsRequired),
            0x10 => Ok(Self::SuccessfullyActivated),
            0x11 => Ok(Self::ConfirmationRequired),
            other => Err(DoipError::UnknownRoutingActivationResponseCode(other)),
        }
    }
}

impl From<ActivationResponseCode> for u8 {
    fn from(code: ActivationResponseCode) -> Self {
        code as Self
    }
}

impl ActivationResponseCode {
    /// Returns `true` if this code represents a successful or pending-confirmation activation.
    #[must_use]
    pub fn is_success(self) -> bool {
        matches!(
            self,
            Self::SuccessfullyActivated | Self::ConfirmationRequired
        )
    }
}

/// Routing activation types per ISO 13400-2:2019 Table 24.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum ActivationType {
    /// Default routing activation (`0x00`)
    Default = 0x00,
    /// WWH-OBD routing activation (`0x01`)
    WwhObd = 0x01,
    /// Central security routing activation (`0xE0`)
    CentralSecurity = 0xE0,
}

impl TryFrom<u8> for ActivationType {
    type Error = DoipError;

    fn try_from(value: u8) -> std::result::Result<Self, Self::Error> {
        match value {
            0x00 => Ok(Self::Default),
            0x01 => Ok(Self::WwhObd),
            0xE0 => Ok(Self::CentralSecurity),
            other => Err(DoipError::UnknownActivationType(other)),
        }
    }
}

/// Routing Activation Request (payload type `0x0005`) – sent by the tester
/// to activate a routing path.
///
/// # Wire Format
/// Payload: SA(2) + type(1) + reserved(4) + optional OEM(4)
///
/// `Clone` is derived because [`DoipPayload`](super::payload::DoipPayload) wraps this type and itself derives `Clone`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RoutingActivationRequest {
    source_address: u16,
    activation_type: ActivationType,
    reserved: u32,
    oem_specific: Option<u32>,
}

impl RoutingActivationRequest {
    /// Minimum wire-format length of a Routing Activation Request payload
    /// (7 bytes: SA + type + reserved, without OEM data).
    pub(crate) const MIN_LEN: usize = 7;
    /// Maximum wire-format length of a Routing Activation Request payload
    /// (11 bytes: includes optional 4-byte OEM data).
    pub(crate) const MAX_LEN: usize = 11;

    /// Tester logical source address
    #[must_use]
    pub fn source_address(&self) -> u16 {
        self.source_address
    }

    /// Activation type requested
    #[must_use]
    pub fn activation_type(&self) -> ActivationType {
        self.activation_type
    }

    /// Reserved field (must be 0x00000000)
    #[must_use]
    pub fn reserved(&self) -> u32 {
        self.reserved
    }

    /// Optional OEM-specific data
    #[must_use]
    pub fn oem_specific(&self) -> Option<u32> {
        self.oem_specific
    }
}

/// Routing Activation Response (payload type `0x0006`) – sent by the `DoIP`
/// entity to confirm or deny routing.
///
/// # Wire Format
/// Payload: testerAddr(2) + entityAddr(2) + code(1) + reserved(4) + optional OEM(4)
///
/// `Clone` is derived because [`DoipPayload`](super::payload::DoipPayload) wraps this type and itself derives `Clone`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RoutingActivationResponse {
    tester_address: u16,
    entity_address: u16,
    code: ActivationResponseCode,
    reserved: u32,
    oem_specific: Option<u32>,
}

impl RoutingActivationResponse {
    /// Minimum wire-format length of a Routing Activation Response payload
    /// (9 bytes: tester addr + entity addr + code + reserved, without OEM data).
    pub(crate) const MIN_LEN: usize = 9;
    /// Maximum wire-format length of a Routing Activation Response payload
    /// (13 bytes: includes optional 4-byte OEM data).
    pub(crate) const MAX_LEN: usize = 13;

    /// Build a successful routing activation response.
    #[must_use]
    pub fn success(tester_address: u16, entity_address: u16) -> Self {
        Self {
            tester_address,
            entity_address,
            code: ActivationResponseCode::SuccessfullyActivated,
            reserved: 0,
            oem_specific: None,
        }
    }

    /// Build a denied routing activation response with the given `code`.
    #[must_use]
    pub fn denial(tester_address: u16, entity_address: u16, code: ActivationResponseCode) -> Self {
        Self {
            tester_address,
            entity_address,
            code,
            reserved: 0,
            oem_specific: None,
        }
    }

    /// Returns `true` if the response code indicates successful or pending-confirmation activation.
    #[must_use]
    pub fn is_success(&self) -> bool {
        self.code.is_success()
    }

    /// Tester logical address
    #[must_use]
    pub fn tester_address(&self) -> u16 {
        self.tester_address
    }

    /// `DoIP` entity logical address
    #[must_use]
    pub fn entity_address(&self) -> u16 {
        self.entity_address
    }

    /// Routing activation response code
    #[must_use]
    pub fn response_code(&self) -> ActivationResponseCode {
        self.code
    }

    /// Reserved field
    #[must_use]
    pub fn reserved(&self) -> u32 {
        self.reserved
    }

    /// Optional OEM-specific data
    #[must_use]
    pub fn oem_specific(&self) -> Option<u32> {
        self.oem_specific
    }

    /// Attach OEM-specific data to this response.
    #[must_use]
    pub fn with_oem_specific(mut self, oem: u32) -> Self {
        self.oem_specific = Some(oem);
        self
    }
}

impl DoipParseable for RoutingActivationRequest {
    fn parse(payload: &[u8]) -> Result<Self> {
        let header: [u8; Self::MIN_LEN] = parse_fixed_slice(payload, "RoutingActivation Request")?;

        let source_address = u16::from_be_bytes([header[0], header[1]]);
        let activation_type = ActivationType::try_from(header[2]).map_err(|e| {
            error!(error = %e, "RoutingActivation Request parse failed");
            e
        })?;
        let reserved = u32::from_be_bytes([header[3], header[4], header[5], header[6]]);

        let oem_specific = parse_oem_specific(payload, Self::MIN_LEN, Self::MAX_LEN);

        Ok(Self {
            source_address,
            activation_type,
            reserved,
            oem_specific,
        })
    }
}

impl DoipParseable for RoutingActivationResponse {
    fn parse(payload: &[u8]) -> Result<Self> {
        let header: [u8; Self::MIN_LEN] = parse_fixed_slice(payload, "RoutingActivation Response")?;

        let tester_address = u16::from_be_bytes([header[0], header[1]]);
        let entity_address = u16::from_be_bytes([header[2], header[3]]);
        let response_code = ActivationResponseCode::try_from(header[4]).map_err(|e| {
            error!(error = %e, "RoutingActivation Response parse failed");
            e
        })?;
        let reserved = u32::from_be_bytes([header[5], header[6], header[7], header[8]]);

        let oem_specific = parse_oem_specific(payload, Self::MIN_LEN, Self::MAX_LEN);

        Ok(Self {
            tester_address,
            entity_address,
            code: response_code,
            reserved,
            oem_specific,
        })
    }
}

impl DoipSerializable for RoutingActivationResponse {
    fn serialized_len(&self) -> Option<usize> {
        Some(
            Self::MIN_LEN.saturating_add(if self.oem_specific.is_some() {
                OEM_DATA_LEN
            } else {
                0
            }),
        )
    }

    fn write_to(&self, buf: &mut BytesMut) {
        buf.put_u16(self.tester_address);
        buf.put_u16(self.entity_address);
        buf.put_u8(u8::from(self.code));
        buf.put_u32(self.reserved);
        if let Some(oem) = self.oem_specific {
            buf.put_u32(oem);
        }
    }
}

#[cfg(test)]
#[allow(clippy::indexing_slicing)]
mod tests {
    use super::*;
    use crate::doip::{DoipParseable, DoipSerializable};

    // Wire-format byte offsets for RoutingActivation Response
    // Layout: TesterAddr(2) + EntityAddr(2) + ActivationResponseCode(1) + Reserved(4) + OEM(4 optional)
    const TESTER_ADDR_END: usize = 2;
    const ENTITY_ADDR_END: usize = 4;
    const RESP_CODE_IDX: usize = 4;
    const OEM_DATA_START: usize = RoutingActivationResponse::MIN_LEN; // 9
    const OEM_DATA_END: usize = RoutingActivationResponse::MAX_LEN; // 13

    #[test]
    fn response_code_success_check() {
        assert!(ActivationResponseCode::SuccessfullyActivated.is_success());
        assert!(ActivationResponseCode::ConfirmationRequired.is_success());
        assert!(!ActivationResponseCode::UnknownSourceAddress.is_success());
        assert!(!ActivationResponseCode::TlsRequired.is_success());
    }

    #[test]
    fn response_code_values() {
        assert_eq!(ActivationResponseCode::UnknownSourceAddress as u8, 0x00);
        assert_eq!(ActivationResponseCode::SuccessfullyActivated as u8, 0x10);
        assert_eq!(ActivationResponseCode::ConfirmationRequired as u8, 0x11);
    }

    #[test]
    fn parse_minimal_request() {
        let payload = [0x0E, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00];
        let req = RoutingActivationRequest::parse(&payload).unwrap();

        assert_eq!(req.source_address(), 0x0E80);
        assert_eq!(req.activation_type(), ActivationType::Default);
        assert_eq!(req.reserved(), 0);
        assert!(req.oem_specific().is_none());
    }

    #[test]
    fn parse_request_with_oem() {
        let payload = [
            0x0E, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0xDE, 0xAD, 0xBE, 0xEF,
        ];
        let req = RoutingActivationRequest::parse(&payload).unwrap();
        assert_eq!(req.oem_specific(), Some(0xDEAD_BEEF));
    }

    #[test]
    fn parse_wwh_obd_request() {
        let payload = [0x0F, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00];
        let req = RoutingActivationRequest::parse(&payload).unwrap();
        assert_eq!(req.activation_type(), ActivationType::WwhObd);
    }

    #[test]
    fn reject_short_request() {
        let short = [0x0E, 0x80, 0x00, 0x00];
        assert!(RoutingActivationRequest::parse(&short).is_err());
    }

    #[test]
    fn reject_unknown_activation_type() {
        // 0x99 is not a valid ActivationType — parse must fail, not silently accept
        let payload = [0x0E, 0x80, 0x99, 0x00, 0x00, 0x00, 0x00];
        assert!(RoutingActivationRequest::parse(&payload).is_err());
    }

    #[test]
    fn build_success_response() {
        let resp = RoutingActivationResponse::success(0x0E80, 0x1000);
        assert_eq!(resp.tester_address(), 0x0E80);
        assert_eq!(resp.entity_address(), 0x1000);
        assert!(resp.is_success());
    }

    #[test]
    fn build_denial_response() {
        let resp = RoutingActivationResponse::denial(
            0x0E80,
            0x1000,
            ActivationResponseCode::AllSocketsRegistered,
        );
        assert!(!resp.is_success());
    }

    #[test]
    fn serialize_response() {
        let resp = RoutingActivationResponse::success(0x0E80, 0x1000);
        let bytes = resp.to_bytes();

        assert_eq!(bytes.len(), RoutingActivationResponse::MIN_LEN);
        assert_eq!(&bytes[..TESTER_ADDR_END], &[0x0E, 0x80]);
        assert_eq!(&bytes[TESTER_ADDR_END..ENTITY_ADDR_END], &[0x10, 0x00]);
        assert_eq!(
            bytes[RESP_CODE_IDX],
            ActivationResponseCode::SuccessfullyActivated as u8
        );
    }

    #[test]
    fn serialize_response_with_oem() {
        let resp =
            RoutingActivationResponse::success(0x0E80, 0x1000).with_oem_specific(0x1234_5678);
        let bytes = resp.to_bytes();

        assert_eq!(bytes.len(), RoutingActivationResponse::MAX_LEN);
        assert_eq!(
            &bytes[OEM_DATA_START..OEM_DATA_END],
            &[0x12, 0x34, 0x56, 0x78]
        );
    }

    #[test]
    fn parse_success_response() {
        let payload = [0x0E, 0x80, 0x10, 0x00, 0x10, 0x00, 0x00, 0x00, 0x00];
        let resp = RoutingActivationResponse::parse(&payload).unwrap();
        assert!(resp.is_success());
        assert_eq!(resp.tester_address(), 0x0E80);
        assert_eq!(resp.entity_address(), 0x1000);
    }

    #[test]
    fn parse_denial_response() {
        let payload = [0x0E, 0x80, 0x10, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00];
        let resp = RoutingActivationResponse::parse(&payload).unwrap();
        assert!(!resp.is_success());
        assert_eq!(
            resp.response_code(),
            ActivationResponseCode::AllSocketsRegistered
        );
    }

    #[test]
    fn roundtrip_response() {
        let original = RoutingActivationResponse::success(0x0E80, 0x1000);
        let bytes = original.to_bytes();
        let parsed = RoutingActivationResponse::parse(&bytes).unwrap();
        assert_eq!(original, parsed);
    }

    #[test]
    fn roundtrip_response_with_oem() {
        let mut original = RoutingActivationResponse::denial(
            0x0F00,
            0x2000,
            ActivationResponseCode::MissingAuthentication,
        );
        original.oem_specific = Some(0xCAFE_BABE);
        let bytes = original.to_bytes();
        let parsed = RoutingActivationResponse::parse(&bytes).unwrap();
        assert_eq!(original, parsed);
    }
}
