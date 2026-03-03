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
//! Error Types for `DoIP` Server (ISO 13400-2:2019 & ISO 14229-1:2020)

use std::io;
use thiserror::Error;

// Re-export from the canonical definitions in the protocol modules
pub use crate::doip::diagnostic_message::NackCode as DiagnosticNackCode;
pub use crate::doip::header_parser::GenericNackCode;
pub use crate::doip::routing_activation::ResponseCode as RoutingActivationCode;

/// Result type alias for `DoIP` operations
pub type DoipResult<T> = std::result::Result<T, DoipError>;

/// Main `DoIP` Error type
#[derive(Error, Debug)]
pub enum DoipError {
    #[error("I/O error: {0}")]
    Io(#[from] io::Error),

    #[error("Configuration error: {0}")]
    InvalidConfig(String),

    #[error("Invalid protocol version: expected 0x{expected:02X}, got 0x{actual:02X}")]
    InvalidProtocolVersion { expected: u8, actual: u8 },

    #[error("Invalid DoIP header: {0}")]
    InvalidHeader(String),

    #[error("Unknown payload type: 0x{0:04X}")]
    UnknownPayloadType(u16),

    #[error("payload too short: need {expected} bytes, got {actual}")]
    PayloadTooShort { expected: usize, actual: usize },

    #[error("unknown routing activation response code: {0:#04x}")]
    UnknownRoutingActivationResponseCode(u8),

    #[error("unknown activation type: {0:#04x}")]
    UnknownActivationType(u8),

    #[error("unknown diagnostic nack code: {0:#04x}")]
    UnknownNackCode(u8),

    #[error("diagnostic message has no user data")]
    EmptyUserData,

    #[error("invalid VIN length: expected 17, got {0}")]
    InvalidVinLength(usize),

    #[error("invalid EID length: expected 6, got {0}")]
    InvalidEidLength(usize),

    #[error("Message too large: {size} bytes (max: {max})")]
    MessageTooLarge { size: usize, max: usize },

    #[error("Routing activation failed: {message}")]
    RoutingActivationFailed { code: u8, message: String },

    #[error("Session not found")]
    SessionNotFound,

    #[error("Session closed")]
    SessionClosed,

    #[error("Timeout: {0}")]
    Timeout(String),

    #[error("UDS error: service 0x{service:02X}, NRC 0x{nrc:02X}")]
    UdsError { service: u8, nrc: u8 },
}

/// UDS Negative Response Codes (ISO 14229-1:2020)
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum UdsNrc {
    GeneralReject = 0x10,
    ServiceNotSupported = 0x11,
    SubFunctionNotSupported = 0x12,
    IncorrectMessageLength = 0x13,
    BusyRepeatRequest = 0x21,
    ConditionsNotCorrect = 0x22,
    RequestSequenceError = 0x24,
    RequestOutOfRange = 0x31,
    SecurityAccessDenied = 0x33,
    InvalidKey = 0x35,
    ExceededNumberOfAttempts = 0x36,
    RequiredTimeDelayNotExpired = 0x37,
    ResponsePending = 0x78,
    ServiceNotSupportedInActiveSession = 0x7F,
}

impl UdsNrc {
    #[must_use]
    pub const fn as_u8(self) -> u8 {
        self as u8
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_routing_activation_success() {
        assert!(RoutingActivationCode::SuccessfullyActivated.is_success());
        assert!(!RoutingActivationCode::UnknownSourceAddress.is_success());
    }

    #[test]
    fn test_nrc_values() {
        assert_eq!(UdsNrc::ServiceNotSupported.as_u8(), 0x11);
        assert_eq!(DiagnosticNackCode::UnknownTargetAddress as u8, 0x03);
    }

    #[test]
    fn test_generic_nack_code_values() {
        let cases = [
            (GenericNackCode::IncorrectPatternFormat, 0x00),
            (GenericNackCode::UnknownPayloadType, 0x01),
            (GenericNackCode::MessageTooLarge, 0x02),
            (GenericNackCode::OutOfMemory, 0x03),
            (GenericNackCode::InvalidPayloadLength, 0x04),
        ];
        for (code, expected) in cases {
            assert_eq!(code as u8, expected);
        }
    }

    #[test]
    fn test_routing_activation_code_values() {
        let cases = [
            (RoutingActivationCode::UnknownSourceAddress, 0x00),
            (RoutingActivationCode::AllSocketsRegistered, 0x01),
            (RoutingActivationCode::DifferentSourceAddress, 0x02),
            (RoutingActivationCode::SourceAddressAlreadyActive, 0x03),
            (RoutingActivationCode::MissingAuthentication, 0x04),
            (RoutingActivationCode::RejectedConfirmation, 0x05),
            (RoutingActivationCode::UnsupportedActivationType, 0x06),
            (RoutingActivationCode::SuccessfullyActivated, 0x10),
            (RoutingActivationCode::ConfirmationRequired, 0x11),
        ];
        for (code, expected) in cases {
            assert_eq!(code as u8, expected);
        }
    }

    #[test]
    fn test_diagnostic_nack_code_values() {
        let cases = [
            (DiagnosticNackCode::InvalidSourceAddress, 0x02),
            (DiagnosticNackCode::UnknownTargetAddress, 0x03),
            (DiagnosticNackCode::DiagnosticMessageTooLarge, 0x04),
            (DiagnosticNackCode::OutOfMemory, 0x05),
            (DiagnosticNackCode::TargetUnreachable, 0x06),
            (DiagnosticNackCode::UnknownNetwork, 0x07),
            (DiagnosticNackCode::TransportProtocolError, 0x08),
        ];
        for (code, expected) in cases {
            assert_eq!(code as u8, expected);
        }
    }

    #[test]
    fn test_uds_nrc_values() {
        let cases = [
            (UdsNrc::GeneralReject, 0x10),
            (UdsNrc::ServiceNotSupported, 0x11),
            (UdsNrc::SubFunctionNotSupported, 0x12),
            (UdsNrc::IncorrectMessageLength, 0x13),
            (UdsNrc::BusyRepeatRequest, 0x21),
            (UdsNrc::ConditionsNotCorrect, 0x22),
            (UdsNrc::RequestSequenceError, 0x24),
            (UdsNrc::RequestOutOfRange, 0x31),
            (UdsNrc::SecurityAccessDenied, 0x33),
            (UdsNrc::InvalidKey, 0x35),
            (UdsNrc::ExceededNumberOfAttempts, 0x36),
            (UdsNrc::RequiredTimeDelayNotExpired, 0x37),
            (UdsNrc::ResponsePending, 0x78),
            (UdsNrc::ServiceNotSupportedInActiveSession, 0x7F),
        ];
        for (code, expected) in cases {
            assert_eq!(code.as_u8(), expected);
        }
    }

    #[test]
    fn test_doip_error_display_variants() {
        let errors = [
            DoipError::Io(io::Error::other("io")),
            DoipError::InvalidConfig("bad config".to_string()),
            DoipError::InvalidProtocolVersion {
                expected: 0x02,
                actual: 0x00,
            },
            DoipError::InvalidHeader("bad header".to_string()),
            DoipError::UnknownPayloadType(0x1234),
            DoipError::MessageTooLarge { size: 10, max: 1 },
            DoipError::RoutingActivationFailed {
                code: 0x00,
                message: "fail".to_string(),
            },
            DoipError::SessionNotFound,
            DoipError::SessionClosed,
            DoipError::Timeout("timeout".to_string()),
            DoipError::UdsError {
                service: 0x10,
                nrc: 0x11,
            },
            DoipError::PayloadTooShort {
                expected: 8,
                actual: 4,
            },
            DoipError::UnknownRoutingActivationResponseCode(0x99),
            DoipError::EmptyUserData,
            DoipError::InvalidVinLength(10),
            DoipError::InvalidEidLength(4),
        ];

        for err in errors {
            let _ = err.to_string();
        }
    }
}
