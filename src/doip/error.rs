// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 The Contributors to Eclipse OpenSOVD (see CONTRIBUTORS)
//
// See the NOTICE file(s) distributed with this work for additional
// information regarding copyright ownership.
//
// This program and the accompanying materials are made available under the
// terms of the Apache License Version 2.0 which is available at
// https://www.apache.org/licenses/LICENSE-2.0

//! DoIP protocol and handler errors.

use crate::doip::message::DoipNackCode;
use crate::proxy::SovdProxyError;

/// Errors returned while parsing or handling DoIP messages.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// Returned when the protocol version byte is invalid.
    #[error("invalid header version: expected 0xFD, got {0:#x}")]
    InvalidHeaderVersion(u8),

    /// Returned when the inverse protocol version byte is invalid.
    #[error("invalid inverse version: expected 0x02, got {0:#x}")]
    InvalidInverseVersion(u8),

    /// Returned when no handler or payload enum variant exists for a payload type.
    #[error("unknown DoIP payload type: {0:#06x}")]
    UnknownPayloadType(u16),

    /// Returned when the payload length does not match the protocol requirement.
    #[error("invalid payload length: expected {expected}, got {actual}")]
    InvalidPayloadLength { expected: u32, actual: usize },

    /// Returned when a payload is shorter than required.
    #[error("payload too short: expected at least {expected} bytes, got {actual}")]
    PayloadTooShort { expected: usize, actual: usize },

    /// Returned when a payload exceeds the accepted size.
    #[error("payload length {0} exceeds maximum allowed size")]
    PayloadTooLarge(usize),

    /// Returned when a payload is present where none is allowed.
    #[error("unexpected payload: expected {expected} bytes, got {actual}")]
    UnexpectedPayload { expected: usize, actual: usize },

    /// Returned when backend diagnostic processing fails.
    #[error("SOVD proxy error: {0}")]
    Proxy(#[from] SovdProxyError),

    /// Returned when a vehicle-identification EID does not match this entity.
    #[error("no matching EID for request")]
    EIDNotMatched,

    /// Returned when a vehicle-identification VIN does not match this entity.
    #[error("no matching VIN for request")]
    VinNotMatched,
}

impl Error {
    /// Returns the Generic Header NACK code associated with this error.
    pub fn nack_code(&self) -> DoipNackCode {
        match self {
            Error::InvalidHeaderVersion(_) | Error::InvalidInverseVersion(_) => {
                DoipNackCode::IncorrectPattern
            }
            Error::UnknownPayloadType(_) => DoipNackCode::UnknownPayloadType,
            Error::PayloadTooLarge(_) => DoipNackCode::MessageTooLarge,
            Error::InvalidPayloadLength { .. }
            | Error::PayloadTooShort { .. }
            | Error::UnexpectedPayload { .. } => DoipNackCode::InvalidPayloadLength,
            Error::Proxy(_) => DoipNackCode::IncorrectPattern,
            Error::EIDNotMatched | Error::VinNotMatched => DoipNackCode::IncorrectPattern,
        }
    }
}
