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

use std::{io, net::AddrParseError};

use thiserror::Error;

/// Result type alias for `DoIP` operations
pub type Result<T> = std::result::Result<T, DoipError>;

/// Main `DoIP` Error type
#[non_exhaustive]
#[derive(Error, Debug)]
pub enum DoipError {
    #[error("I/O error: {0}")]
    Io(#[from] io::Error),

    #[error("configuration error: {0}")]
    InvalidConfig(String),

    #[error("configuration file error: {0}")]
    ConfigFileError(String),

    #[error("hex decode error: {0}")]
    HexDecodeError(String),

    #[error("invalid address: {0}")]
    InvalidAddress(#[from] AddrParseError),

    #[error("invalid DoIP header: {0}")]
    InvalidHeader(String),

    #[error("unknown payload type: 0x{0:04X}")]
    UnknownPayloadType(u16),

    #[error("payload too short: need {expected} bytes, got {actual}")]
    PayloadTooShort { expected: usize, actual: usize },

    #[error("unknown routing activation response code: {0:#04x}")]
    UnknownRoutingActivationResponseCode(u8),

    #[error("unknown activation type: {0:#04x}")]
    UnknownActivationType(u8),

    #[error("unknown diagnostic nack code: {0:#04x}")]
    UnknownNackCode(u8),

    #[error("unknown further action byte: {0:#04x}")]
    UnknownFurtherAction(u8),

    #[error("unknown sync status byte: {0:#04x}")]
    UnknownSyncStatus(u8),

    #[error("diagnostic message has no user data")]
    EmptyUserData,

    #[error("unexpected payload data: expected empty payload, got {actual} bytes")]
    UnexpectedPayload { actual: usize },
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn error_display_variants() {
        // Smoke-test every DoipError variant produces a non-empty Display string.
        let errors = [
            DoipError::Io(io::Error::other("io")),
            DoipError::InvalidConfig("bad config".to_string()),
            DoipError::InvalidHeader("bad header".to_string()),
            DoipError::UnknownPayloadType(0x1234),
            DoipError::PayloadTooShort {
                expected: 8,
                actual: 4,
            },
            DoipError::UnknownRoutingActivationResponseCode(0x99),
            DoipError::EmptyUserData,
        ];
        for err in errors {
            assert!(!err.to_string().is_empty());
        }
    }
}
