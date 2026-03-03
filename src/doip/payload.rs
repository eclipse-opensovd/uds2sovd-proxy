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
//! Typed dispatch envelope for DoIP message payloads (ISO 13400-2:2019).
//!
//! [`DoipPayload`] is a strongly-typed enum that wraps every concrete payload
//! struct. Use [`DoipPayload::parse`] to decode a raw [`DoipMessage`] into
//! the correct variant in one step, instead of manually matching on
//! [`PayloadType`] throughout the codebase.
//!
//! # Example
//! ```ignore
//! let payload = DoipPayload::parse(&msg)?;
//! match payload {
//!     DoipPayload::DiagnosticMessage(m) => handle_diag(m),
//!     DoipPayload::AliveCheckRequest(_) => send_alive_response(),
//!     _ => {}
//! }
//! ```

use super::{
    alive_check, diagnostic_message, routing_activation, vehicle_id, DoipMessage, DoipParseable,
    GenericNackCode, PayloadType,
};
use crate::DoipError;

/// A fully-parsed DoIP message payload.
///
/// Each variant corresponds to one [`PayloadType`] and wraps the concrete
/// struct returned by its [`DoipParseable`] impl.
#[derive(Debug, Clone)]
pub enum DoipPayload {
    /// `0x0007` – Alive Check Request (zero-length payload)
    AliveCheckRequest(alive_check::Request),
    /// `0x0008` – Alive Check Response
    AliveCheckResponse(alive_check::Response),
    /// `0x0005` – Routing Activation Request
    RoutingActivationRequest(routing_activation::Request),
    /// `0x0006` – Routing Activation Response
    RoutingActivationResponse(routing_activation::Response),
    /// `0x8001` – Diagnostic Message (UDS data)
    DiagnosticMessage(diagnostic_message::Message),
    /// `0x8002` – Diagnostic Message Positive Acknowledgement
    DiagnosticMessagePositiveAck(diagnostic_message::PositiveAck),
    /// `0x8003` – Diagnostic Message Negative Acknowledgement
    DiagnosticMessageNegativeAck(diagnostic_message::NegativeAck),
    /// `0x0001` – Vehicle Identification Request (no filter)
    VehicleIdentificationRequest(vehicle_id::Request),
    /// `0x0002` – Vehicle Identification Request filtered by EID
    VehicleIdentificationRequestWithEid(vehicle_id::RequestWithEid),
    /// `0x0003` – Vehicle Identification Request filtered by VIN
    VehicleIdentificationRequestWithVin(vehicle_id::RequestWithVin),
    /// `0x0004` – Vehicle Identification Response / Announce
    VehicleIdentificationResponse(vehicle_id::Response),
    /// `0x0000` – Generic DoIP Header Negative Acknowledgement
    GenericNack(GenericNackCode),
}

impl DoipPayload {
    /// Decode the payload of a [`DoipMessage`] into a typed [`DoipPayload`] variant.
    ///
    /// # Errors
    /// Returns [`DoipError::UnknownPayloadType`] when the `payload_type` field
    /// in the header does not map to a known [`PayloadType`] variant, or when
    /// the DoIP payload byte is not a recognized `GenericNackCode`.
    ///
    /// Returns a more specific [`DoipError`] (e.g. [`DoipError::PayloadTooShort`])
    /// when the payload bytes are present but malformed.
    pub fn parse(msg: &DoipMessage) -> std::result::Result<Self, DoipError> {
        let payload = msg.payload.as_ref();

        let payload_type = msg
            .payload_type()
            .ok_or(DoipError::UnknownPayloadType(msg.header.payload_type))?;

        match payload_type {
            PayloadType::AliveCheckRequest => Ok(Self::AliveCheckRequest(
                alive_check::Request::parse(payload)?,
            )),
            PayloadType::AliveCheckResponse => Ok(Self::AliveCheckResponse(
                alive_check::Response::parse(payload)?,
            )),
            PayloadType::RoutingActivationRequest => Ok(Self::RoutingActivationRequest(
                routing_activation::Request::parse(payload)?,
            )),
            PayloadType::RoutingActivationResponse => Ok(Self::RoutingActivationResponse(
                routing_activation::Response::parse(payload)?,
            )),
            PayloadType::DiagnosticMessage => Ok(Self::DiagnosticMessage(
                diagnostic_message::Message::parse(payload)?,
            )),
            PayloadType::DiagnosticMessagePositiveAck => Ok(Self::DiagnosticMessagePositiveAck(
                diagnostic_message::PositiveAck::parse(payload)?,
            )),
            PayloadType::DiagnosticMessageNegativeAck => Ok(Self::DiagnosticMessageNegativeAck(
                diagnostic_message::NegativeAck::parse(payload)?,
            )),
            PayloadType::VehicleIdentificationRequest => Ok(Self::VehicleIdentificationRequest(
                vehicle_id::Request::parse(payload)?,
            )),
            PayloadType::VehicleIdentificationRequestWithEid => {
                Ok(Self::VehicleIdentificationRequestWithEid(
                    vehicle_id::RequestWithEid::parse(payload)?,
                ))
            }
            PayloadType::VehicleIdentificationRequestWithVin => {
                Ok(Self::VehicleIdentificationRequestWithVin(
                    vehicle_id::RequestWithVin::parse(payload)?,
                ))
            }
            PayloadType::VehicleIdentificationResponse => Ok(Self::VehicleIdentificationResponse(
                vehicle_id::Response::parse(payload)?,
            )),
            PayloadType::GenericNack => {
                let byte = payload.first().copied().ok_or(DoipError::PayloadTooShort {
                    expected: 1,
                    actual: 0,
                })?;
                let code = GenericNackCode::try_from(byte)
                    .map_err(|b| DoipError::UnknownPayloadType(u16::from(b)))?;
                Ok(Self::GenericNack(code))
            }
            PayloadType::DoipEntityStatusRequest
            | PayloadType::DoipEntityStatusResponse
            | PayloadType::DiagnosticPowerModeRequest
            | PayloadType::DiagnosticPowerModeResponse => {
                Err(DoipError::UnknownPayloadType(payload_type as u16))
            }
        }
    }

    /// Return the [`PayloadType`] that corresponds to this payload variant.
    #[must_use]
    pub fn payload_type(&self) -> PayloadType {
        match self {
            Self::AliveCheckRequest(_) => PayloadType::AliveCheckRequest,
            Self::AliveCheckResponse(_) => PayloadType::AliveCheckResponse,
            Self::RoutingActivationRequest(_) => PayloadType::RoutingActivationRequest,
            Self::RoutingActivationResponse(_) => PayloadType::RoutingActivationResponse,
            Self::DiagnosticMessage(_) => PayloadType::DiagnosticMessage,
            Self::DiagnosticMessagePositiveAck(_) => PayloadType::DiagnosticMessagePositiveAck,
            Self::DiagnosticMessageNegativeAck(_) => PayloadType::DiagnosticMessageNegativeAck,
            Self::VehicleIdentificationRequest(_) => PayloadType::VehicleIdentificationRequest,
            Self::VehicleIdentificationRequestWithEid(_) => {
                PayloadType::VehicleIdentificationRequestWithEid
            }
            Self::VehicleIdentificationRequestWithVin(_) => {
                PayloadType::VehicleIdentificationRequestWithVin
            }
            Self::VehicleIdentificationResponse(_) => PayloadType::VehicleIdentificationResponse,
            Self::GenericNack(_) => PayloadType::GenericNack,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::doip::{DoipMessage, PayloadType};
    use bytes::Bytes;

    fn make_msg(payload_type: PayloadType, payload: impl Into<Bytes>) -> DoipMessage {
        DoipMessage {
            header: crate::doip::DoipHeader {
                version: crate::doip::DEFAULT_PROTOCOL_VERSION,
                inverse_version: crate::doip::DEFAULT_PROTOCOL_VERSION_INV,
                payload_type: payload_type as u16,
                payload_length: 0,
            },
            payload: payload.into(),
        }
    }

    #[test]
    fn alive_check_request_roundtrip() {
        let msg = make_msg(PayloadType::AliveCheckRequest, vec![]);
        let parsed = DoipPayload::parse(&msg).unwrap();
        assert!(matches!(parsed, DoipPayload::AliveCheckRequest(_)));
        assert_eq!(parsed.payload_type(), PayloadType::AliveCheckRequest);
    }

    #[test]
    fn alive_check_response_roundtrip() {
        let msg = make_msg(PayloadType::AliveCheckResponse, vec![0x0E, 0x80]);
        let parsed = DoipPayload::parse(&msg).unwrap();
        assert!(matches!(parsed, DoipPayload::AliveCheckResponse(_)));
    }

    #[test]
    fn routing_activation_request_roundtrip() {
        let payload = vec![0x0E, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00];
        let msg = make_msg(PayloadType::RoutingActivationRequest, payload);
        let parsed = DoipPayload::parse(&msg).unwrap();
        assert!(matches!(parsed, DoipPayload::RoutingActivationRequest(_)));
    }

    #[test]
    fn routing_activation_response_roundtrip() {
        use crate::doip::DoipSerializable;
        let resp = routing_activation::Response::success(0x0E80, 0x1000);
        let msg = make_msg(PayloadType::RoutingActivationResponse, resp.to_bytes());
        let parsed = DoipPayload::parse(&msg).unwrap();
        assert!(matches!(parsed, DoipPayload::RoutingActivationResponse(_)));
    }

    #[test]
    fn generic_nack_roundtrip() {
        let msg = make_msg(PayloadType::GenericNack, vec![0x02]);
        let parsed = DoipPayload::parse(&msg).unwrap();
        assert!(matches!(
            parsed,
            DoipPayload::GenericNack(GenericNackCode::MessageTooLarge)
        ));
    }

    #[test]
    fn unknown_payload_type_error() {
        let msg = DoipMessage {
            header: crate::doip::DoipHeader {
                version: crate::doip::DEFAULT_PROTOCOL_VERSION,
                inverse_version: crate::doip::DEFAULT_PROTOCOL_VERSION_INV,
                payload_type: 0xFFFF,
                payload_length: 0,
            },
            payload: Bytes::new(),
        };
        let err = DoipPayload::parse(&msg).unwrap_err();
        assert!(matches!(err, crate::DoipError::UnknownPayloadType(0xFFFF)));
    }

    #[test]
    fn missing_alive_check_response_data_errors() {
        let msg = make_msg(PayloadType::AliveCheckResponse, vec![]);
        assert!(DoipPayload::parse(&msg).is_err());
    }

    #[test]
    fn payload_type_round_trips() {
        assert_eq!(
            DoipPayload::GenericNack(GenericNackCode::MessageTooLarge).payload_type(),
            PayloadType::GenericNack,
        );
    }
}
