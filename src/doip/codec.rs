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

//! `DoIP` TCP Codec
//!
//! Provides a Tokio [`Decoder`]/[`Encoder`] pair for framing `DoIP` messages over TCP
//! streams according to ISO 13400-2:2019. A simple two-state machine handles reassembly
//! across packet boundaries:
//!
//! 1. **Header** – wait for 8 bytes, validate, then transition to Payload.
//! 2. **Payload** – wait for the declared payload length, then emit a [`DoipMessage`].
//!
//! See [`header`](super::header) for the underlying type definitions.

use bytes::BytesMut;
use std::io;
use tokio_util::codec::{Decoder, Encoder};
use tracing::{debug, warn};

use super::header::{DOIP_HEADER_LENGTH, DoipHeader, DoipMessage, MAX_DOIP_MESSAGE_SIZE};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum DecodeState {
    Header,
    Payload(DoipHeader),
}

const DEFAULT_MAX_PAYLOAD_SIZE: u32 = MAX_DOIP_MESSAGE_SIZE;

/// `DoIP` TCP Codec
///
/// Implements the Tokio [`Decoder`] / [`Encoder`] trait pair to frame raw TCP bytes
/// into [`DoipMessage`] values and vice-versa.
///
/// The codec enforces a configurable maximum payload size (default 4 MB) to provide
/// `DoS` protection against oversized message attacks.
#[derive(Debug)]
pub struct DoipCodec {
    state: DecodeState,
    max_payload_size: u32,
}

impl DoipCodec {
    #[must_use]
    pub fn new() -> Self {
        Self {
            state: DecodeState::Header,
            max_payload_size: DEFAULT_MAX_PAYLOAD_SIZE,
        }
    }

    /// Create codec with custom max payload size limit
    ///
    /// The size is u32 to match the `DoIP` header `payload_length` field (4 bytes).
    /// This provides `DoS` protection by rejecting oversized messages early.
    #[must_use]
    pub fn with_max_payload_size(max_size: u32) -> Self {
        Self {
            state: DecodeState::Header,
            max_payload_size: max_size,
        }
    }
}

impl Default for DoipCodec {
    fn default() -> Self {
        Self::new()
    }
}

impl Decoder for DoipCodec {
    type Item = DoipMessage;
    type Error = io::Error;

    fn decode(
        &mut self,
        src: &mut BytesMut,
    ) -> std::result::Result<Option<Self::Item>, Self::Error> {
        loop {
            match self.state {
                DecodeState::Header => {
                    if src.len() < DOIP_HEADER_LENGTH {
                        // Reserve space to reduce reallocations when more data arrives
                        src.reserve(DOIP_HEADER_LENGTH);
                        return Ok(None);
                    }

                    // Log raw bytes for debugging
                    let header_slice = src.get(..DOIP_HEADER_LENGTH).ok_or_else(|| {
                        io::Error::new(io::ErrorKind::InvalidData, "buffer too short")
                    })?;
                    debug!("Received raw header bytes: {:02X?}", header_slice);

                    let header = DoipHeader::parse(header_slice)
                        .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;

                    if let Some(nack_code) = header.validate() {
                        warn!(
                            "Header validation failed: {:?} - raw bytes: {:02X?}",
                            nack_code, header_slice
                        );
                        return Err(io::Error::new(
                            io::ErrorKind::InvalidData,
                            format!("validation failed: {nack_code:?}"),
                        ));
                    }

                    if header.payload_length() > self.max_payload_size {
                        return Err(io::Error::new(
                            io::ErrorKind::InvalidData,
                            format!(
                                "payload too large: {} > {}",
                                header.payload_length(),
                                self.max_payload_size
                            ),
                        ));
                    }

                    // Pre-allocate buffer for the complete message (best-effort hint)
                    if let Some(reserve_len) = header.message_length() {
                        src.reserve(reserve_len);
                    }
                    self.state = DecodeState::Payload(header);
                }

                DecodeState::Payload(header) => {
                    let Some(total_len) = header.message_length() else {
                        return Err(io::Error::new(
                            io::ErrorKind::InvalidData,
                            "payload length overflows usize",
                        ));
                    };
                    if src.len() < total_len {
                        // Still waiting for complete payload - this is normal for large messages
                        // or when data arrives in multiple TCP packets
                        return Ok(None);
                    }

                    let _ = src.split_to(DOIP_HEADER_LENGTH);
                    let payload = src.split_to(total_len - DOIP_HEADER_LENGTH).freeze();

                    self.state = DecodeState::Header;
                    return Ok(Some(DoipMessage { header, payload }));
                }
            }
        }
    }
}

impl Encoder<DoipMessage> for DoipCodec {
    type Error = io::Error;

    fn encode(
        &mut self,
        item: DoipMessage,
        dst: &mut BytesMut,
    ) -> std::result::Result<(), Self::Error> {
        dst.reserve(item.message_length());
        item.header.write_to(dst);
        dst.extend_from_slice(&item.payload);
        Ok(())
    }
}
