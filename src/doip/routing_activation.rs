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

use super::{DoipParseable, DoipSerializable, check_min_len, parse_fixed_slice};
use crate::DoipError;
use bytes::{Buf, BufMut, Bytes, BytesMut};
use tracing::warn;

/// Routing activation response codes per ISO 13400-2:2019 Table 25.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum ResponseCode {
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

impl TryFrom<u8> for ResponseCode {
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

impl From<ResponseCode> for u8 {
    fn from(code: ResponseCode) -> u8 {
        code as u8
    }
}

impl ResponseCode {
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

// Routing Activation Request - payload is 7 bytes min, 11 with OEM data
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Request {
    source_address: u16,
    activation_type: ActivationType,
    reserved: u32,
    oem_specific: Option<u32>,
}

impl Request {
    pub const MIN_LEN: usize = 7;
    pub const MAX_LEN: usize = 11;

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

    /// Parse routing activation request from buffer
    ///
    /// # Errors
    ///
    /// Returns an error if the buffer is too short or contains invalid data.
    pub fn parse_buf(buf: &mut Bytes) -> std::result::Result<Self, DoipError> {
        check_min_len(buf.as_ref(), Self::MIN_LEN)?;

        let source_address = buf.get_u16();
        let activation_type = ActivationType::try_from(buf.get_u8()).map_err(|e| {
            warn!("RoutingActivation Request parse_buf: {}", e);
            e
        })?;
        let reserved = buf.get_u32();
        let oem_specific = if buf.remaining() >= 4 {
            Some(buf.get_u32())
        } else {
            None
        };

        Ok(Self {
            source_address,
            activation_type,
            reserved,
            oem_specific,
        })
    }
}

// Routing Activation Response - 9 bytes min, 13 with OEM data
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Response {
    tester_address: u16,
    entity_address: u16,
    code: ResponseCode,
    reserved: u32,
    oem_specific: Option<u32>,
}

impl Response {
    pub const MIN_LEN: usize = 9;
    pub const MAX_LEN: usize = 13;

    /// Build a successful routing activation response.
    #[must_use]
    pub fn success(tester_address: u16, entity_address: u16) -> Self {
        Self {
            tester_address,
            entity_address,
            code: ResponseCode::SuccessfullyActivated,
            reserved: 0,
            oem_specific: None,
        }
    }

    /// Build a denied routing activation response with the given `code`.
    #[must_use]
    pub fn denial(tester_address: u16, entity_address: u16, code: ResponseCode) -> Self {
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
    pub fn response_code(&self) -> ResponseCode {
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
}

impl DoipParseable for Request {
    fn parse(payload: &[u8]) -> std::result::Result<Self, DoipError> {
        let header: [u8; Self::MIN_LEN] = parse_fixed_slice(payload, "RoutingActivation Request")?;

        let source_address = u16::from_be_bytes([header[0], header[1]]);
        let activation_type = ActivationType::try_from(header[2]).map_err(|e| {
            warn!("RoutingActivation Request parse failed: {}", e);
            e
        })?;
        let reserved = u32::from_be_bytes([header[3], header[4], header[5], header[6]]);

        let oem_specific = payload
            .get(Self::MIN_LEN..Self::MAX_LEN)
            .and_then(|s| <[u8; 4]>::try_from(s).ok())
            .map(u32::from_be_bytes);

        Ok(Self {
            source_address,
            activation_type,
            reserved,
            oem_specific,
        })
    }
}

impl DoipParseable for Response {
    fn parse(payload: &[u8]) -> std::result::Result<Self, DoipError> {
        let header: [u8; Self::MIN_LEN] = parse_fixed_slice(payload, "RoutingActivation Response")?;

        let tester_address = u16::from_be_bytes([header[0], header[1]]);
        let entity_address = u16::from_be_bytes([header[2], header[3]]);
        let response_code = ResponseCode::try_from(header[4]).map_err(|e| {
            warn!("RoutingActivation Response parse failed: {}", e);
            e
        })?;
        let reserved = u32::from_be_bytes([header[5], header[6], header[7], header[8]]);

        let oem_specific = payload
            .get(Self::MIN_LEN..Self::MAX_LEN)
            .and_then(|s| <[u8; 4]>::try_from(s).ok())
            .map(u32::from_be_bytes);

        Ok(Self {
            tester_address,
            entity_address,
            code: response_code,
            reserved,
            oem_specific,
        })
    }
}

impl DoipSerializable for Response {
    fn serialized_len(&self) -> Option<usize> {
        Some(Self::MIN_LEN + if self.oem_specific.is_some() { 4 } else { 0 })
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
mod tests {
    use super::*;
    use crate::doip::{DoipParseable, DoipSerializable};

    // Wire-format byte offsets for RoutingActivation Response
    // Layout: TesterAddr(2) + EntityAddr(2) + ResponseCode(1) + Reserved(4) + OEM(4 optional)
    const TESTER_ADDR_END: usize = 2;
    const ENTITY_ADDR_END: usize = 4;
    const RESP_CODE_IDX: usize = 4;
    const OEM_DATA_START: usize = Response::MIN_LEN; // 9
    const OEM_DATA_END: usize = Response::MAX_LEN; // 13

    #[test]
    fn response_code_success_check() {
        assert!(ResponseCode::SuccessfullyActivated.is_success());
        assert!(ResponseCode::ConfirmationRequired.is_success());
        assert!(!ResponseCode::UnknownSourceAddress.is_success());
        assert!(!ResponseCode::TlsRequired.is_success());
    }

    #[test]
    fn response_code_values() {
        assert_eq!(ResponseCode::UnknownSourceAddress as u8, 0x00);
        assert_eq!(ResponseCode::SuccessfullyActivated as u8, 0x10);
        assert_eq!(ResponseCode::ConfirmationRequired as u8, 0x11);
    }

    #[test]
    fn parse_minimal_request() {
        let payload = [0x0E, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00];
        let req = Request::parse(&payload).unwrap();

        assert_eq!(req.source_address, 0x0E80);
        assert_eq!(req.activation_type, ActivationType::Default);
        assert_eq!(req.reserved, 0);
        assert!(req.oem_specific.is_none());
    }

    #[test]
    fn parse_request_with_oem() {
        let payload = [
            0x0E, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0xDE, 0xAD, 0xBE, 0xEF,
        ];
        let req = Request::parse(&payload).unwrap();
        assert_eq!(req.oem_specific, Some(0xDEAD_BEEF));
    }

    #[test]
    fn parse_wwh_obd_request() {
        let payload = [0x0F, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00];
        let req = Request::parse(&payload).unwrap();
        assert_eq!(req.activation_type, ActivationType::WwhObd);
    }

    #[test]
    fn reject_short_request() {
        let short = [0x0E, 0x80, 0x00, 0x00];
        assert!(Request::parse(&short).is_err());
    }

    #[test]
    fn reject_unknown_activation_type() {
        // 0x99 is not a valid ActivationType — parse must fail, not silently accept
        let payload = [0x0E, 0x80, 0x99, 0x00, 0x00, 0x00, 0x00];
        assert!(Request::parse(&payload).is_err());
    }

    #[test]
    fn build_success_response() {
        let resp = Response::success(0x0E80, 0x1000);
        assert_eq!(resp.tester_address, 0x0E80);
        assert_eq!(resp.entity_address, 0x1000);
        assert!(resp.is_success());
    }

    #[test]
    fn build_denial_response() {
        let resp = Response::denial(0x0E80, 0x1000, ResponseCode::AllSocketsRegistered);
        assert!(!resp.is_success());
    }

    #[test]
    fn serialize_response() {
        let resp = Response::success(0x0E80, 0x1000);
        let bytes = resp.to_bytes();

        assert_eq!(bytes.len(), Response::MIN_LEN);
        assert_eq!(&bytes[..TESTER_ADDR_END], &[0x0E, 0x80]);
        assert_eq!(&bytes[TESTER_ADDR_END..ENTITY_ADDR_END], &[0x10, 0x00]);
        assert_eq!(
            bytes[RESP_CODE_IDX],
            ResponseCode::SuccessfullyActivated as u8
        );
    }

    #[test]
    fn serialize_response_with_oem() {
        let mut resp = Response::success(0x0E80, 0x1000);
        resp.oem_specific = Some(0x1234_5678);
        let bytes = resp.to_bytes();

        assert_eq!(bytes.len(), Response::MAX_LEN);
        assert_eq!(
            &bytes[OEM_DATA_START..OEM_DATA_END],
            &[0x12, 0x34, 0x56, 0x78]
        );
    }

    #[test]
    fn parse_success_response() {
        let payload = [0x0E, 0x80, 0x10, 0x00, 0x10, 0x00, 0x00, 0x00, 0x00];
        let resp = Response::parse(&payload).unwrap();
        assert!(resp.is_success());
        assert_eq!(resp.tester_address, 0x0E80);
        assert_eq!(resp.entity_address, 0x1000);
    }

    #[test]
    fn parse_denial_response() {
        let payload = [0x0E, 0x80, 0x10, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00];
        let resp = Response::parse(&payload).unwrap();
        assert!(!resp.is_success());
        assert_eq!(resp.response_code(), ResponseCode::AllSocketsRegistered);
    }

    #[test]
    fn roundtrip_response() {
        let original = Response::success(0x0E80, 0x1000);
        let bytes = original.to_bytes();
        let parsed = Response::parse(&bytes).unwrap();
        assert_eq!(original, parsed);
    }

    #[test]
    fn roundtrip_response_with_oem() {
        let mut original = Response::denial(0x0F00, 0x2000, ResponseCode::MissingAuthentication);
        original.oem_specific = Some(0xCAFE_BABE);
        let bytes = original.to_bytes();
        let parsed = Response::parse(&bytes).unwrap();
        assert_eq!(original, parsed);
    }
}
