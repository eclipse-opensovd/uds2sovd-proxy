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
//!
//! This module provides the core `DoIP` protocol types and codec for TCP/UDP communication.

/// Alive Check request/response handlers (ISO 13400-2:2019 §7.6).
pub mod alive_check;
/// Tokio codec framing for DoIP TCP streams.
pub mod codec;
/// Diagnostic Message request and acknowledgment handlers (ISO 13400-2:2019 §7.9).
pub mod diagnostic_message;
/// DoIP header parsing, validation, and serialization.
pub mod header;
/// DoIP payload type enumeration and dispatch.
pub mod payload;
/// Routing Activation request/response handlers (ISO 13400-2:2019 §7.7).
pub mod routing_activation;
/// Vehicle Identification request/response handlers (ISO 13400-2:2019 §7.5).
pub mod vehicle_id;

// Re-export core types and constants for convenient access.
// Constants are exported to allow external testing and custom DoIP message construction.
use bytes::{Bytes, BytesMut};
pub use codec::DoipCodec;
pub use header::{
    DEFAULT_PROTOCOL_VERSION, DOIP_HEADER_LENGTH, DoipHeader, DoipMessage, GenericNackCode,
    MAX_DOIP_MESSAGE_SIZE, PayloadType,
};
pub use payload::DoipPayload;
use tracing::error;

use crate::{DoipError, Result};

/// Trait for `DoIP` message types that can be parsed from a raw payload slice.
///
/// Implement this for every message struct so callers can decode incoming
/// `DoIP` frames through a uniform interface.
pub(crate) trait DoipParseable: Sized {
    /// Parse a `DoIP` message from a raw payload byte slice.
    ///
    /// # Errors
    /// Returns [`DoipError`] if the payload is malformed or too short.
    fn parse(payload: &[u8]) -> Result<Self>;
}

/// Trait for `DoIP` message types that can be serialized to a [`Bytes`] buffer.
///
/// Implement [`write_to`](DoipSerializable::write_to) with the wire-format logic.
/// The default [`to_bytes`](DoipSerializable::to_bytes) wraps it in a `BytesMut`
/// and calls `freeze()`, so you never write that boilerplate again.
pub trait DoipSerializable {
    /// Write the serialized wire-format bytes into `buf`.
    fn write_to(&self, buf: &mut BytesMut);

    /// Returns `Some(n)` when the size is known ahead of serialization,
    /// enabling [`to_bytes`](DoipSerializable::to_bytes) to pre-allocate the buffer
    /// and avoid incremental `BytesMut` reallocations for large messages.
    ///
    /// Returns `None` (the default) to indicate the size is not known in
    /// advance; [`to_bytes`](DoipSerializable::to_bytes) will then use a
    /// dynamically-growing buffer. Override this in your implementation whenever
    /// the encoded length is computable upfront.
    fn serialized_len(&self) -> Option<usize> {
        None
    }

    /// Serialize this message into a [`Bytes`] buffer.
    ///
    /// Pre-allocates the buffer when [`serialized_len`](DoipSerializable::serialized_len)
    /// returns `Some`.
    fn to_bytes(&self) -> Bytes {
        let mut buf = self
            .serialized_len()
            .map_or_else(BytesMut::new, BytesMut::with_capacity);
        self.write_to(&mut buf);
        buf.freeze()
    }
}

/// Build a [`DoipError::PayloadTooShort`] from the given slice and expected length.
pub(crate) fn too_short(payload: &[u8], expected: usize) -> DoipError {
    DoipError::PayloadTooShort {
        expected,
        actual: payload.len(),
    }
}

/// Return `Err` if `payload` is shorter than `expected` bytes.
pub(crate) fn check_min_len(payload: &[u8], expected: usize) -> Result<()> {
    if payload.len() < expected {
        Err(too_short(payload, expected))
    } else {
        Ok(())
    }
}

/// Extract the first `N` bytes of `payload` as a fixed-size array.
///
/// Logs an error and returns [`DoipError::PayloadTooShort`] when the slice
/// is shorter than `N` bytes, using `context` to identify the call site in the log.
pub(crate) fn parse_fixed_slice<const N: usize>(payload: &[u8], context: &str) -> Result<[u8; N]> {
    payload
        .get(..N)
        .and_then(|s| s.try_into().ok())
        .ok_or_else(|| {
            let e = too_short(payload, N);
            error!(context, error = %e, "parse failed");
            e
        })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::DoipError;

    #[test]
    fn too_short_produces_correct_error() {
        let payload = [0x01u8, 0x02];
        let err = too_short(&payload, 5);
        assert!(matches!(
            err,
            DoipError::PayloadTooShort {
                expected: 5,
                actual: 2
            }
        ));
    }

    #[test]
    fn too_short_on_empty_slice() {
        let err = too_short(&[], 4);
        assert!(matches!(
            err,
            DoipError::PayloadTooShort {
                expected: 4,
                actual: 0
            }
        ));
    }

    #[test]
    fn check_min_len_passes_when_exact() {
        assert!(check_min_len(&[0x01, 0x02], 2).is_ok());
    }

    #[test]
    fn check_min_len_passes_when_longer() {
        assert!(check_min_len(&[0x01, 0x02, 0x03], 2).is_ok());
    }

    #[test]
    fn check_min_len_errors_when_too_short() {
        let result = check_min_len(&[0x01], 2);
        assert!(matches!(
            result,
            Err(DoipError::PayloadTooShort {
                expected: 2,
                actual: 1
            })
        ));
    }

    #[test]
    fn check_min_len_errors_on_empty_slice() {
        let result = check_min_len(&[], 1);
        assert!(matches!(
            result,
            Err(DoipError::PayloadTooShort {
                expected: 1,
                actual: 0
            })
        ));
    }

    #[test]
    fn check_min_len_zero_always_passes() {
        assert!(check_min_len(&[], 0).is_ok());
    }

    #[test]
    fn parse_fixed_slice_extracts_exact_bytes() {
        let payload = [0x0E, 0x80, 0x10, 0x01];
        let result: [u8; 2] = parse_fixed_slice(&payload, "test").unwrap();
        assert_eq!(result, [0x0E, 0x80]);
    }

    #[test]
    fn parse_fixed_slice_succeeds_with_extra_bytes() {
        let payload = [0x01, 0x02, 0x03, 0x04, 0x05];
        let result: [u8; 3] = parse_fixed_slice(&payload, "test").unwrap();
        assert_eq!(result, [0x01, 0x02, 0x03]);
    }

    #[test]
    fn parse_fixed_slice_errors_when_too_short() {
        let payload = [0x01u8];
        let result: crate::Result<[u8; 4]> = parse_fixed_slice(&payload, "test");
        assert!(matches!(
            result,
            Err(DoipError::PayloadTooShort {
                expected: 4,
                actual: 1
            })
        ));
    }

    #[test]
    fn parse_fixed_slice_errors_on_empty() {
        let result: crate::Result<[u8; 2]> = parse_fixed_slice(&[], "context");
        assert!(matches!(
            result,
            Err(DoipError::PayloadTooShort {
                expected: 2,
                actual: 0
            })
        ));
    }

    #[test]
    fn parse_fixed_slice_zero_size_always_succeeds() {
        let result: [u8; 0] = parse_fixed_slice(&[], "empty").unwrap();
        assert_eq!(result, []);
    }
}
