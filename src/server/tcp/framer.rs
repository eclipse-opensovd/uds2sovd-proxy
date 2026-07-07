// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 The Contributors to Eclipse OpenSOVD (see CONTRIBUTORS)
//
// See the NOTICE file(s) distributed with this work for additional
// information regarding copyright ownership.
//
// This program and the accompanying materials are made available under the
// terms of the Apache License Version 2.0 which is available at
// https://www.apache.org/licenses/LICENSE-2.0

use crate::doip::constants::{HEADER_LEN, MAX_DOIP_PAYLOAD_LEN};
use crate::doip::error::Error;
use crate::doip::header::DoipHeader;
use crate::doip::message::TcpPayloadType;

/// A fully validated DoIP frame parsed from the TCP byte stream.
#[derive(Debug)]
pub struct Frame {
    payload_type: TcpPayloadType,
    payload: Vec<u8>,
}

impl Frame {
    /// Consume the frame, returning the payload type and raw bytes.
    pub fn into_parts(self) -> (TcpPayloadType, Vec<u8>) {
        (self.payload_type, self.payload)
    }
}

/// Stateful byte-stream framer for DoIP over TCP.
///
/// # Framing strategy
///
/// DoIP has no start-of-frame markers or escape sequences. Framing relies
/// entirely on the length field in the 8-byte header. Once a frame is parsed,
/// the framer commits to that interpretation — there's no way to resynchronize
/// mid-stream if corruption occurs.
///
/// # Error handling
///
/// - **Protocol errors** (`InvalidHeaderVersion`, `InvalidInverseVersion`):
///   Parsing stops immediately. The connection must be closed per ISO 13400-2  7.2.
/// - **Oversized frames**: Entire frame is skipped when complete. Partial frames
///   wait for more data to avoid misinterpreting payload as header.
/// - **Unknown payload types**: Frame is consumed and error returned, but parsing
///   continues for subsequent frames.
pub struct Framer {
    buffer: Vec<u8>,
}

impl Framer {
    /// Creates a framer with an empty internal buffer.
    pub fn new() -> Self {
        Self { buffer: Vec::new() }
    }

    /// Feed raw bytes in; receive zero or more complete frames (or per-frame errors) out.
    ///
    /// # Framing guarantees
    ///
    /// - A framing error on one frame does NOT discard subsequent buffered data
    ///   (exception: protocol version errors trigger immediate stop).
    /// - Partial frames remain in buffer until complete.
    /// - Oversized frames are only skipped after receiving all declared bytes.
    ///
    /// # Protocol version errors
    ///
    /// If `InvalidHeaderVersion` or `InvalidInverseVersion` is returned, the caller
    /// MUST close the TCP connection. DoIP provides no recovery mechanism for these errors.
    pub fn feed(&mut self, bytes: &[u8]) -> Vec<Result<Frame, Error>> {
        self.buffer.extend_from_slice(bytes);
        let mut frames = Vec::new();

        loop {
            if self.buffer.len() < HEADER_LEN {
                break; // not enough bytes for a header yet
            }

            // Parse and validate the 8-byte DoIP generic header
            let header = match DoipHeader::parse(&self.buffer[..HEADER_LEN]) {
                Ok(h) => h,
                Err(e) => {
                    // Protocol version errors — no recovery possible mid-stream.
                    // Return error and let connection handler close per ISO 13400-2  7.2
                    frames.push(Err(e));
                    break;
                }
            };

            let payload_type_raw = header.payload_type_raw;
            let payload_len = header.payload_len;

            // ISO 13400-2: max DoIP payload size is 64KB for standard diagnostics.

            if payload_len > MAX_DOIP_PAYLOAD_LEN {
                frames.push(Err(Error::PayloadTooLarge(payload_len)));
                // Corner case: Must drain ENTIRE frame (header + payload), not just header.
                // Draining only header would cause payload bytes to be misinterpreted as
                // the next header, breaking frame synchronization.
                //
                // Additional edge case: If payload hasn't fully arrived yet, we must wait
                // rather than drain partial data, otherwise we'd skip into the middle of
                // the oversized payload and lose sync.
                let total_len = HEADER_LEN + payload_len;
                if self.buffer.len() >= total_len {
                    self.buffer.drain(..total_len);
                } else {
                    break; // Wait for complete frame before skipping
                }
                continue;
            }

            let total_len = HEADER_LEN + payload_len;
            if self.buffer.len() < total_len {
                break; // payload not yet fully received — wait for more data
            }

            let payload_type = match TcpPayloadType::try_from(payload_type_raw) {
                Ok(parsed_type) => parsed_type,
                Err(raw) => {
                    frames.push(Err(Error::UnknownPayloadType(raw)));
                    self.buffer.drain(..total_len);
                    continue;
                }
            };

            let payload = self.buffer[HEADER_LEN..total_len].to_vec();
            self.buffer.drain(..total_len);
            frames.push(Ok(Frame {
                payload_type,
                payload,
            }));
        }

        frames
    }
}

impl Default for Framer {
    /// Note: `#[derive(new)]` can be considered in future if similar patterns grow across the codebase.    
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn raw_frame(payload_type: u16, payload: &[u8]) -> Vec<u8> {
        let mut buf = vec![0xFD, 0x02];
        buf.extend_from_slice(&payload_type.to_be_bytes());
        buf.extend_from_slice(&(payload.len() as u32).to_be_bytes());
        buf.extend_from_slice(payload);
        buf
    }

    #[test]
    fn single_complete_frame_emitted() {
        let mut f = Framer::new();
        let raw = raw_frame(0x0007, &[]); // AliveCheckRequest, empty payload
        let mut out = f.feed(&raw);
        assert_eq!(out.len(), 1);
        let (pt, payload) = out.remove(0).unwrap().into_parts();
        assert_eq!(pt, TcpPayloadType::AliveCheckRequest);
        assert!(payload.is_empty());
    }

    #[test]
    fn header_split_across_two_feeds() {
        let mut f = Framer::new();
        let raw = raw_frame(0x0007, &[]);
        assert!(
            f.feed(&raw[..4]).is_empty(),
            "partial header yields no frame"
        );
        let out = f.feed(&raw[4..]);
        assert_eq!(out.len(), 1);
        assert!(out[0].is_ok());
    }

    #[test]
    fn payload_split_across_two_feeds() {
        let mut f = Framer::new();
        let payload = vec![0xAA, 0xBB, 0xCC, 0xDD];
        let raw = raw_frame(0x0007, &payload);
        let mid = raw.len() / 2;
        assert!(
            f.feed(&raw[..mid]).is_empty(),
            "partial payload yields no frame"
        );
        let mut out = f.feed(&raw[mid..]);
        assert_eq!(out.len(), 1);
        let (_, frame_payload) = out.remove(0).unwrap().into_parts();
        assert_eq!(frame_payload, payload);
    }

    #[test]
    fn two_messages_packed_in_one_feed() {
        let mut f = Framer::new();
        let mut raw = raw_frame(0x0007, &[]); // AliveCheckRequest
        raw.extend(raw_frame(
            0x0005,
            &[0x00, 0x01, 0x00, 0, 0, 0, 0, 0, 0, 0, 0],
        )); // RoutingActivation
        let out = f.feed(&raw);
        assert_eq!(out.len(), 2);
        assert!(out[0].is_ok());
        assert!(out[1].is_ok());
    }

    #[test]
    fn invalid_protocol_version_returns_error() {
        let mut f = Framer::new();
        let mut raw = raw_frame(0x0007, &[]);
        raw[0] = 0x01; // corrupt version byte
        let out = f.feed(&raw);
        assert_eq!(out.len(), 1);
        assert!(matches!(out[0], Err(Error::InvalidHeaderVersion(0x01))));
    }

    #[test]
    fn unknown_payload_type_returns_error() {
        let mut f = Framer::new();
        let raw = raw_frame(0xDEAD, &[]); // not a valid TcpPayloadType
        let out = f.feed(&raw);
        assert_eq!(out.len(), 1);
        assert!(matches!(out[0], Err(Error::UnknownPayloadType(0xDEAD))));
    }

    #[test]
    fn good_frame_after_bad_frame_is_recovered() {
        let mut f = Framer::new();
        let mut raw = raw_frame(0xDEAD, &[]); // bad frame
        raw.extend(raw_frame(0x0007, &[])); // good frame after
        let out = f.feed(&raw);
        assert_eq!(out.len(), 2);
        assert!(out[0].is_err());
        assert!(out[1].is_ok());
    }

    #[test]
    fn invalid_inverse_version_returns_error() {
        let mut f = Framer::new();
        let mut raw = raw_frame(0x0007, &[]);
        raw[1] = 0xAB; // corrupt inverse version byte
        let out = f.feed(&raw);
        assert_eq!(out.len(), 1);
        assert!(matches!(out[0], Err(Error::InvalidInverseVersion(0xAB))));
    }

    #[test]
    fn payload_too_large_returns_error() {
        let mut f = Framer::new();
        // Header declaring 65536 bytes (exceeds MAX_PAYLOAD_LEN of 65535)
        let mut raw = vec![0xFD, 0x02];
        raw.extend_from_slice(&0x0007u16.to_be_bytes());
        raw.extend_from_slice(&65_536u32.to_be_bytes());
        let out = f.feed(&raw);
        assert_eq!(out.len(), 1);
        assert!(matches!(out[0], Err(Error::PayloadTooLarge(65_536))));
    }
}
