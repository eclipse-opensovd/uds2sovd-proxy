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

//! Error types for the UDS-to-SOVD proxy.
//!
//! [`ProxyError`] is the top-level error used throughout the crate. Sub-errors
//! for UDS ([`UdsError`]) and SOVD ([`SovdError`]) convert into it automatically
//! via the `?` operator through the generated [`From`] implementations.

use thiserror::Error;

/// Proxy-level result type alias.
pub type Result<T> = std::result::Result<T, ProxyError>;

/// Top-level error type for the UDS-to-SOVD proxy.
#[derive(Debug, Error)]
pub enum ProxyError {
    /// Configuration loading or validation error.
    #[error("Configuration error: {0}")]
    Config(String),

    /// MDD database / service resolution error.
    #[error("MDD error: {0}")]
    Mdd(String),

    /// UDS protocol layer error.
    #[error("UDS error: {0}")]
    Uds(#[from] UdsError),

    /// SOVD gateway communication error.
    #[error("SOVD error: {0}")]
    Sovd(#[from] SovdError),

    /// I/O error (socket, file, etc.).
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
}

/// UDS-layer error type.
#[derive(Debug, Error)]
pub enum UdsError {
    /// Message is shorter or longer than required by the service specification.
    #[error("Invalid message length: expected {expected}, got {actual}")]
    InvalidLength {
        /// Number of bytes the service requires.
        expected: usize,
        /// Number of bytes actually present in the message.
        actual: usize,
    },

    /// The Data Identifier (DID) in the request is not known to the MDD.
    #[error("Invalid DID: {0:#06x}")]
    InvalidDid(u16),
}

/// SOVD gateway communication error type.
#[derive(Debug, Error)]
pub enum SovdError {
    /// Network-level transport failure — DNS resolution, connection refused,
    /// TLS handshake, timeout, or response-body parse error.
    #[error("Transport error: {0}")]
    Transport(String),

    /// The SOVD server returned an unexpected HTTP status code.
    #[error("HTTP {status}: {body}")]
    HttpStatus {
        /// HTTP status code returned by the server.
        status: u16,
        /// Response body text (may be empty).
        body: String,
    },

    /// `OAuth2` client-credentials exchange was rejected by the gateway.
    #[error("Authentication failed (HTTP {status}): {body}")]
    Auth {
        /// HTTP status code returned by the auth endpoint.
        status: u16,
        /// Response body text from the auth endpoint.
        body: String,
    },

    /// The requested SOVD endpoint was not found on the server (HTTP 404).
    #[error("Endpoint not found: '{endpoint}'")]
    EndpointNotFound {
        /// The SOVD service endpoint identifier that was not found.
        endpoint: String,
    },

    /// SOVD JSON response structure does not match the expected MDD schema.
    #[error("Schema mismatch for '{service}': {reason}")]
    SchemaMismatch {
        /// The MDD service name whose schema was being validated.
        service: String,
        /// Human-readable description of what did not match.
        reason: String,
    },

    /// The MDD database contains no POS-RESPONSE metadata for this service.
    #[error("Missing MDD metadata for service '{service}'")]
    MetadataMissing {
        /// The MDD service name that lacks POS-RESPONSE parameter metadata.
        service: String,
    },
}

/// UDS Negative Response Codes (NRC) — ISO 14229-1 Table A-1.
///
/// Only the codes used by this proxy are enumerated here. The discriminant
/// value matches the wire byte.  Use [`From<Nrc> for u8`] for explicit
/// conversion; do **not** use `nrc as u8` in new code.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum Nrc {
    /// Service not supported (0x11).
    ServiceNotSupported = 0x11,
    /// Incorrect message length or invalid format (0x13).
    IncorrectMessageLengthOrInvalidFormat = 0x13,
    /// Request out of range (0x31).
    RequestOutOfRange = 0x31,
    /// General programming failure (0x72).
    GeneralProgrammingFailure = 0x72,
}

impl From<Nrc> for u8 {
    fn from(nrc: Nrc) -> Self {
        nrc as u8
    }
}

impl Nrc {
    /// Build a 3-byte ISO 14229-1 negative response frame.
    ///
    /// The returned array has the form `[0x7F, request_sid, nrc_byte]` as
    /// defined in ISO 14229-1 #8.6.
    ///
    /// # Example
    /// ```
    /// use uds::error::Nrc;
    ///
    /// let frame = Nrc::ServiceNotSupported.response_for(0x22);
    /// assert_eq!(frame, [0x7F, 0x22, 0x11]);
    /// ```
    #[must_use]
    pub fn response_for(self, request_sid: u8) -> [u8; 3] {
        [0x7F, request_sid, u8::from(self)]
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn nrc_from_converts_to_wire_byte() {
        assert_eq!(u8::from(Nrc::ServiceNotSupported), 0x11);
        assert_eq!(u8::from(Nrc::IncorrectMessageLengthOrInvalidFormat), 0x13);
        assert_eq!(u8::from(Nrc::RequestOutOfRange), 0x31);
        assert_eq!(u8::from(Nrc::GeneralProgrammingFailure), 0x72);
    }

    #[test]
    fn response_for_produces_correct_frame() {
        let frame = Nrc::ServiceNotSupported.response_for(0x22);
        assert_eq!(frame, [0x7F, 0x22, 0x11]);
    }

    #[test]
    fn response_for_preserves_request_sid() {
        let frame = Nrc::RequestOutOfRange.response_for(0x2E);
        assert_eq!(frame[0], 0x7F, "first byte must be negative response SID");
        assert_eq!(frame[1], 0x2E, "second byte must echo the request SID");
        assert_eq!(frame[2], 0x31, "third byte must be the NRC wire value");
    }

    #[test]
    fn response_for_unknown_sid_uses_zero() {
        let frame = Nrc::IncorrectMessageLengthOrInvalidFormat.response_for(0x00);
        assert_eq!(frame, [0x7F, 0x00, 0x13]);
    }

    // ── UdsError ──────────────────────────────────────────────────────────────

    #[test]
    fn uds_error_invalid_length_message_includes_values() {
        let e = UdsError::InvalidLength { expected: 3, actual: 1 };
        let s = e.to_string();
        assert!(s.contains('3') && s.contains('1'), "message must include expected and actual");
    }

    #[test]
    fn uds_error_invalid_did_message_includes_hex_did() {
        let e = UdsError::InvalidDid(0xDEAD);
        // thiserror format: "Invalid DID: 0xdead"
        assert!(e.to_string().to_lowercase().contains("dead"));
    }

    #[test]
    fn uds_error_converts_to_proxy_error_via_question_mark() {
        fn inner() -> Result<()> {
            Err(UdsError::InvalidLength { expected: 3, actual: 0 })?;
            Ok(())
        }
        let err = inner().unwrap_err();
        assert!(err.to_string().contains('3'));
    }

    // ── SovdError ─────────────────────────────────────────────────────────────

    #[test]
    fn sovd_error_transport_message_is_preserved() {
        let e = SovdError::Transport("connection refused".into());
        assert!(e.to_string().contains("connection refused"));
    }

    #[test]
    fn sovd_error_http_status_includes_code_and_body() {
        let e = SovdError::HttpStatus { status: 500, body: "internal server error".into() };
        let s = e.to_string();
        assert!(s.contains("500") && s.contains("internal server error"));
    }

    #[test]
    fn sovd_error_auth_includes_status_and_body() {
        let e = SovdError::Auth { status: 401, body: "token expired".into() };
        let s = e.to_string();
        assert!(s.contains("401") && s.contains("token expired"));
    }

    #[test]
    fn sovd_error_endpoint_not_found_includes_endpoint() {
        let e = SovdError::EndpointNotFound { endpoint: "vindataidentifier_read".into() };
        assert!(e.to_string().contains("vindataidentifier_read"));
    }

    #[test]
    fn sovd_error_schema_mismatch_includes_service_and_reason() {
        let e = SovdError::SchemaMismatch {
            service: "VIN_SERVICE".into(),
            reason: "expected array".into(),
        };
        let s = e.to_string();
        assert!(s.contains("VIN_SERVICE") && s.contains("expected array"));
    }

    #[test]
    fn sovd_error_metadata_missing_includes_service() {
        let e = SovdError::MetadataMissing { service: "UNKNOWN_SERVICE".into() };
        assert!(e.to_string().contains("UNKNOWN_SERVICE"));
    }

    #[test]
    fn sovd_error_converts_to_proxy_error() {
        fn inner() -> Result<()> {
            Err(SovdError::Transport("err".into()))?;
            Ok(())
        }
        assert!(inner().is_err());
    }

    // ── ProxyError ────────────────────────────────────────────────────────────

    #[test]
    fn proxy_error_config_message_is_preserved() {
        let e = ProxyError::Config("bad toml".into());
        assert!(e.to_string().contains("bad toml"));
    }

    #[test]
    fn proxy_error_mdd_message_is_preserved() {
        let e = ProxyError::Mdd("file not found".into());
        assert!(e.to_string().contains("file not found"));
    }

    #[test]
    fn proxy_error_io_wraps_std_io_error() {
        let io_err = std::io::Error::new(std::io::ErrorKind::NotFound, "no such file");
        let e = ProxyError::Io(io_err);
        assert!(e.to_string().contains("no such file"));
    }

    // ── Nrc copy / hash ───────────────────────────────────────────────────────

    #[test]
    fn nrc_is_copy() {
        let a = Nrc::ServiceNotSupported;
        let b = a; // Copy
        assert_eq!(a, b);
    }

    #[test]
    fn nrc_debug_contains_variant_name() {
        let s = format!("{:?}", Nrc::RequestOutOfRange);
        assert!(s.contains("RequestOutOfRange"));
    }
}
