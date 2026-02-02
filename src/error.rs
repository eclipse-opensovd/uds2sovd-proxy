//! Error Types for DoIP Server (ISO 13400-2 & ISO 14229)

use std::io;
use thiserror::Error;

/// Result type alias
pub type Result<T> = std::result::Result<T, DoipError>;

/// Main DoIP Error type
#[derive(Error, Debug)]
pub enum DoipError {
    #[error("I/O error: {0}")]
    Io(#[from] io::Error),

    #[error("Configuration error: {0}")]
    Config(String),

    #[error("Invalid protocol version: expected 0x{expected:02X}, got 0x{actual:02X}")]
    InvalidProtocolVersion { expected: u8, actual: u8 },

    #[error("Invalid DoIP header: {0}")]
    InvalidHeader(String),

    #[error("Unknown payload type: 0x{0:04X}")]
    UnknownPayloadType(u16),

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

/// Generic Header NACK codes 
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum GenericNackCode {
    IncorrectPatternFormat = 0x00,
    UnknownPayloadType = 0x01,
    MessageTooLarge = 0x02,
    OutOfMemory = 0x03,
    InvalidPayloadLength = 0x04,
}

impl GenericNackCode {
    pub const fn as_u8(self) -> u8 { self as u8 }
}

/// Routing Activation Response codes
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum RoutingActivationCode {
    UnknownSourceAddress = 0x00,
    AllSocketsRegistered = 0x01,
    DifferentSourceAddress = 0x02,
    SourceAddressAlreadyActive = 0x03,
    MissingAuthentication = 0x04,
    RejectedConfirmation = 0x05,
    UnsupportedActivationType = 0x06,
    SuccessfullyActivated = 0x10,
    ConfirmationRequired = 0x11,
}

impl RoutingActivationCode {
    pub const fn as_u8(self) -> u8 { self as u8 }
    pub const fn is_success(self) -> bool {
        matches!(self, Self::SuccessfullyActivated | Self::ConfirmationRequired)
    }
}

/// Diagnostic Message NACK codes 
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

impl DiagnosticNackCode {
    pub const fn as_u8(self) -> u8 { self as u8 }
}

/// UDS Negative Response Codes 
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
    pub const fn as_u8(self) -> u8 { self as u8 }
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
        assert_eq!(DiagnosticNackCode::UnknownTargetAddress.as_u8(), 0x03);
    }
}