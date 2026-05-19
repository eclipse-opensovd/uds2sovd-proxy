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

use std::io;

use bytes::BytesMut;
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
    /// Create a new `DoipCodec` with the default maximum payload size.
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
                    debug!(header_bytes = ?header_slice, "Received raw header bytes");

                    let header = DoipHeader::parse(header_slice)
                        .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;

                    if let Some(nack_code) = header.validate() {
                        warn!(
                            nack_code = ?nack_code,
                            header_bytes = ?header_slice,
                            "Header validation failed"
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
                    let payload = src
                        .split_to(total_len.saturating_sub(DOIP_HEADER_LENGTH))
                        .freeze();

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

#[cfg(test)]
mod tests {
    use bytes::Bytes;
    use tokio_util::codec::{Decoder, Encoder};

    use super::*;
    use crate::doip::header::{DoipMessage, PayloadType};

    // Build a minimal valid DoIP frame:
    //   version=0x02, inverse=0xFD, payload_type (u16 BE), payload_length (u32 BE), payload
    fn make_frame(payload_type: u16, payload: &[u8]) -> BytesMut {
        let len = u32::try_from(payload.len()).expect("test payload must fit in u32");
        let [t0, t1] = payload_type.to_be_bytes();
        let [l0, l1, l2, l3] = len.to_be_bytes();
        let mut buf = BytesMut::new();
        buf.extend_from_slice(&[0x02, 0xFD, t0, t1, l0, l1, l2, l3]);
        buf.extend_from_slice(payload);
        buf
    }

    #[test]
    fn new_and_default_behave_the_same() {
        // Both should decode the same frame identically
        let mut a = DoipCodec::new();
        let mut b = DoipCodec::default();
        let frame = make_frame(0x0007, &[]);
        let ra = a.decode(&mut frame.clone()).unwrap();
        let rb = b.decode(&mut frame.clone()).unwrap();
        assert_eq!(ra.is_some(), rb.is_some());
    }

    #[test]
    fn new_accepts_large_payload_within_default_limit() {
        // Default codec must not reject reasonable-sized payloads
        let data = vec![0u8; 1024];
        let mut codec = DoipCodec::new();
        let mut buf = make_frame(0x8001, &data);
        assert!(codec.decode(&mut buf).unwrap().is_some());
    }

    #[test]
    fn with_max_payload_size_limits_accepted_size() {
        // A payload 1 byte over the custom limit must be rejected
        let mut codec = DoipCodec::with_max_payload_size(1024);
        let too_large = vec![0u8; 1025];
        let mut buf = make_frame(0x8001, &too_large);
        assert!(codec.decode(&mut buf).is_err());

        // Exactly at the limit must be accepted
        let mut codec2 = DoipCodec::with_max_payload_size(1024);
        let exact = vec![0u8; 1024];
        let mut buf2 = make_frame(0x8001, &exact);
        assert!(codec2.decode(&mut buf2).unwrap().is_some());
    }

    #[test]
    fn decode_alive_check_request() {
        // Alive check request (type 0x0007) has no payload
        let mut codec = DoipCodec::new();
        let mut buf = make_frame(0x0007, &[]);
        let msg = codec.decode(&mut buf).unwrap().unwrap();
        assert_eq!(msg.header.payload_type(), 0x0007);
        assert!(msg.payload.is_empty());
        assert!(buf.is_empty());
    }

    #[test]
    fn decode_message_with_payload() {
        let mut codec = DoipCodec::new();
        let data = [0x0E, 0x80, 0x10, 0x01, 0x3E];
        let mut buf = make_frame(0x8001, &data);
        let msg = codec.decode(&mut buf).unwrap().unwrap();
        assert_eq!(msg.header.payload_type(), 0x8001);
        assert_eq!(&msg.payload[..], &data);
    }

    #[test]
    fn decode_resets_state_for_next_message() {
        // After a successful decode, the codec must accept another frame
        let mut codec = DoipCodec::new();
        let mut buf = make_frame(0x0007, &[]);
        codec.decode(&mut buf).unwrap().unwrap();
        // Buffer is empty — a healthy reset returns None, not an error
        assert!(codec.decode(&mut buf).unwrap().is_none());
    }

    #[test]
    fn decode_back_to_back_frames() {
        let mut codec = DoipCodec::new();
        let mut buf = make_frame(0x0007, &[]);
        buf.extend_from_slice(&make_frame(0x0008, &[0xAA, 0xBB]));

        let m1 = codec.decode(&mut buf).unwrap().unwrap();
        let m2 = codec.decode(&mut buf).unwrap().unwrap();

        assert_eq!(m1.header.payload_type(), 0x0007);
        assert_eq!(m2.header.payload_type(), 0x0008);
        assert!(buf.is_empty());
    }

    #[test]
    fn decode_returns_none_when_header_incomplete() {
        let mut codec = DoipCodec::new();
        // Only 4 of the 8 header bytes present
        let mut buf = BytesMut::from(&[0x02u8, 0xFD, 0x00, 0x07][..]);
        assert!(codec.decode(&mut buf).unwrap().is_none());
    }

    #[test]
    fn decode_returns_none_when_payload_incomplete() {
        let mut codec = DoipCodec::new();
        // AliveCheckResponse (0x0008) minimum is 2 bytes.
        // Declare 4 bytes in the header but only provide 2 → codec must wait.
        let mut buf = make_frame(0x0008, &[0x0E, 0x80, 0x00, 0x00]);
        buf.truncate(buf.len() - 2); // strip last 2 payload bytes
        assert!(codec.decode(&mut buf).unwrap().is_none());
    }

    #[test]
    fn decode_returns_none_on_empty_buffer() {
        let mut codec = DoipCodec::new();
        let mut buf = BytesMut::new();
        assert!(codec.decode(&mut buf).unwrap().is_none());
    }

    #[test]
    fn decode_rejects_invalid_version() {
        let mut codec = DoipCodec::new();
        // version 0x04 is not a valid DoIP protocol version
        let mut buf = BytesMut::from(&[0x04u8, 0xFB, 0x00, 0x07, 0x00, 0x00, 0x00, 0x00][..]);
        assert!(codec.decode(&mut buf).is_err());
    }

    #[test]
    fn decode_rejects_payload_exceeding_max_size() {
        let mut codec = DoipCodec::with_max_payload_size(10);
        // Declare payload_length = 11, over the limit of 10
        let mut buf = BytesMut::from(&[0x02u8, 0xFD, 0x80, 0x01, 0x00, 0x00, 0x00, 0x0B][..]);
        assert!(codec.decode(&mut buf).is_err());
    }

    #[test]
    fn decode_accepts_payload_at_exact_max_size() {
        let data = vec![0u8; 10];
        let mut codec = DoipCodec::with_max_payload_size(10);
        let mut buf = make_frame(0x8001, &data);
        assert!(codec.decode(&mut buf).unwrap().is_some());
    }

    #[test]
    fn encode_produces_correct_wire_bytes() {
        let mut codec = DoipCodec::new();
        let payload = Bytes::from_static(&[0x0E, 0x80, 0x10, 0x01]);
        let msg = DoipMessage::new(PayloadType::DiagnosticMessage, payload);

        let mut buf = BytesMut::new();
        codec.encode(msg, &mut buf).unwrap();

        // Header: version, inverse, type (0x8001), length (0x00000004)
        assert_eq!(buf.get(..2).unwrap(), &[0x02, 0xFD]);
        assert_eq!(buf.get(2..4).unwrap(), &[0x80, 0x01]);
        assert_eq!(buf.get(4..8).unwrap(), &[0x00, 0x00, 0x00, 0x04]);
        assert_eq!(buf.get(8..).unwrap(), &[0x0E, 0x80, 0x10, 0x01]);
    }

    #[test]
    fn encode_empty_payload() {
        let mut codec = DoipCodec::new();
        let msg = DoipMessage::new(PayloadType::AliveCheckRequest, Bytes::new());

        let mut buf = BytesMut::new();
        codec.encode(msg, &mut buf).unwrap();

        assert_eq!(buf.len(), 8); // header only
        assert_eq!(buf.get(4..8).unwrap(), &[0x00, 0x00, 0x00, 0x00]); // zero payload length
    }

    #[test]
    fn roundtrip_encode_then_decode() {
        let mut codec = DoipCodec::new();
        let payload = Bytes::from_static(&[0x0E, 0x80, 0x22, 0xF1, 0x90]);
        let original = DoipMessage::new(PayloadType::DiagnosticMessage, payload);

        let mut buf = BytesMut::new();
        codec.encode(original.clone(), &mut buf).unwrap();
        let decoded = codec.decode(&mut buf).unwrap().unwrap();

        assert_eq!(original.header, decoded.header);
        assert_eq!(original.payload, decoded.payload);
    }
}
