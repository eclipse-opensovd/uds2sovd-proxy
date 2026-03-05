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

pub mod alive_check;
pub mod codec;
pub mod diagnostic_message;
pub mod header;
pub mod payload;
pub mod routing_activation;
pub mod vehicle_id;

use crate::DoipError;
use bytes::{Bytes, BytesMut};
use tracing::warn;

/// Trait for `DoIP` message types that can be parsed from a raw payload slice.
///
/// Implement this for every message struct so callers can decode incoming
/// `DoIP` frames through a uniform interface.
pub trait DoipParseable: Sized {
    /// Parse a `DoIP` message from a raw payload byte slice.
    ///
    /// # Errors
    /// Returns [`DoipError`] if the payload is malformed or too short.
    fn parse(payload: &[u8]) -> std::result::Result<Self, DoipError>;
}

/// Trait for `DoIP` message types that can be serialized to a [`Bytes`] buffer.
///
/// Implement [`write_to`] with the wire-format logic. The default [`to_bytes`]
/// wraps it in a `BytesMut` and calls `freeze()`, so you never write that
/// boilerplate again.
pub trait DoipSerializable {
    /// Write the serialized wire-format bytes into `buf`.
    fn write_to(&self, buf: &mut BytesMut);

    /// Return the exact serialized byte count, if known without encoding.
    ///
    /// Override this to enable pre-allocated buffers in [`to_bytes`], avoiding
    /// incremental `BytesMut` reallocations for large messages.
    fn serialized_len(&self) -> Option<usize> {
        None
    }

    /// Serialize this message into a [`Bytes`] buffer.
    ///
    /// Pre-allocates the buffer when [`serialized_len`] returns `Some`.
    fn to_bytes(&self) -> Bytes {
        let mut buf = match self.serialized_len() {
            Some(n) => BytesMut::with_capacity(n),
            None => BytesMut::new(),
        };
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
pub(crate) fn check_min_len(payload: &[u8], expected: usize) -> std::result::Result<(), DoipError> {
    if payload.len() < expected {
        Err(too_short(payload, expected))
    } else {
        Ok(())
    }
}

/// Extract the first `N` bytes of `payload` as a fixed-size array.
///
/// Logs a warning and returns [`DoipError::PayloadTooShort`] when the slice
/// is shorter than `N` bytes, using `context` to identify the call site in the log.
pub(crate) fn parse_fixed_slice<const N: usize>(
    payload: &[u8],
    context: &str,
) -> std::result::Result<[u8; N], DoipError> {
    payload
        .get(..N)
        .and_then(|s| s.try_into().ok())
        .ok_or_else(|| {
            let e = too_short(payload, N);
            warn!("{} parse failed: {}", context, e);
            e
        })
}

// Re-export core types and constants for convenient access.
// Constants are exported to allow external testing and custom DoIP message construction.
pub use codec::DoipCodec;
pub use header::{
    DEFAULT_PROTOCOL_VERSION, DEFAULT_PROTOCOL_VERSION_INV, DOIP_HEADER_LENGTH,
    DOIP_HEADER_VERSION_MASK, DOIP_VERSION_DEFAULT, DoipHeader, DoipMessage, GenericNackCode,
    MAX_DOIP_MESSAGE_SIZE, PROTOCOL_VERSION_V1, PROTOCOL_VERSION_V3, PayloadType,
};
pub use payload::DoipPayload;
