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

//! Accumulation buffer and `DoIP` frame extractor.
//!
//! [`FrameBuffer`] holds incoming TCP bytes until at least one complete
//! `DoIP` frame is available.  [`FrameResult`] encodes all three possible
//! outcomes of a single extraction attempt, driving the framing loop in
//! `ConnectionHandler`.

use crate::message::{DOIP_HEADER_SIZE, DOIP_PROTOCOL_VERSION, DoIpMessage};

/// Socket read chunk size used for each `read` call.
pub(super) const READ_BUFFER_SIZE: usize = 4_096;

/// Maximum buffered bytes retained while waiting for complete `DoIP` frames.
pub(super) const MAX_STAGED_BUFFER_BYTES: usize = 65_536;

/// Maximum parsed frames per read cycle to keep scheduling fair.
pub(super) const MAX_FRAMES_PER_READ: usize = 128;

/// Result of a single [`FrameBuffer::try_next`] attempt.
pub(super) enum FrameResult {
    /// A complete, valid frame.
    ///
    /// The `usize` is the total byte span: `DOIP_HEADER_SIZE + payload.len()`.
    /// Pass it to [`FrameBuffer::consume`] to advance the buffer.
    Complete(DoIpMessage, usize),

    /// A full header is present but the version bytes are corrupt.
    ///
    /// Call [`FrameBuffer::skip_byte`] to discard one byte and attempt
    /// protocol re-sync before retrying.
    InvalidHeader,

    /// Not enough bytes yet to form a complete frame.
    ///
    /// Wait for more socket data before calling [`FrameBuffer::try_next`] again.
    Incomplete,
}

/// Accumulation buffer for partial `DoIP` TCP frames.
///
/// Bytes are appended with [`push`](FrameBuffer::push) as they arrive from
/// the socket. Frames are extracted one at a time with
/// [`try_next`](FrameBuffer::try_next).
pub(super) struct FrameBuffer {
    inner: Vec<u8>,
}

impl FrameBuffer {
    /// Create a new buffer pre-allocated to `initial_capacity` bytes.
    pub(super) fn new(initial_capacity: usize) -> Self {
        Self {
            inner: Vec::with_capacity(initial_capacity),
        }
    }

    /// Append newly-received socket bytes.
    pub(super) fn push(&mut self, data: &[u8]) {
        self.inner.extend_from_slice(data);
    }

    /// Attempt to extract one complete `DoIP` frame from the front of the buffer.
    ///
    /// Does **not** modify the buffer. The caller must call
    /// [`consume`](Self::consume) or [`skip_byte`](Self::skip_byte) to advance.
    pub(super) fn try_next(&self) -> FrameResult {
        if let Ok(msg) = DoIpMessage::try_from(self.inner.as_slice()) {
            // `TryFrom<&[u8]> for DoIpMessage` verifies that the declared
            // payload length does not exceed available bytes, so `frame_size`
            // is always within bounds.
            let frame_size = DOIP_HEADER_SIZE.saturating_add(msg.payload.len());
            return FrameResult::Complete(msg, frame_size);
        }

        if self.has_invalid_header() {
            return FrameResult::InvalidHeader;
        }

        FrameResult::Incomplete
    }

    /// Remove the leading `n` bytes after successfully consuming one frame.
    pub(super) fn consume(&mut self, n: usize) {
        self.inner.drain(..n);
    }

    /// Discard the first byte to attempt re-sync after a corrupt `DoIP` header.
    ///
    /// No-op on an empty buffer.
    pub(super) fn skip_byte(&mut self) {
        if !self.inner.is_empty() {
            self.inner.drain(..1);
        }
    }

    /// Discard all buffered bytes.
    pub(super) fn clear(&mut self) {
        self.inner.clear();
    }

    /// Returns the number of bytes currently buffered.
    pub(super) fn len(&self) -> usize {
        self.inner.len()
    }

    /// Returns `true` when the buffer contains no bytes.
    #[allow(dead_code)] // required by clippy::len_without_is_empty companion rule
    pub(super) fn is_empty(&self) -> bool {
        self.inner.is_empty()
    }

    /// Returns `true` when the buffer has grown past the overflow threshold.
    ///
    /// The caller should [`clear`](Self::clear) the buffer when this is `true`.
    pub(super) fn is_overflow(&self) -> bool {
        self.inner.len() > MAX_STAGED_BUFFER_BYTES
    }

    /// Returns `true` when a full `DoIP` header is present but the protocol
    /// version bytes do not match the ISO 13400-2 specification.
    fn has_invalid_header(&self) -> bool {
        if self.inner.len() < DOIP_HEADER_SIZE {
            return false;
        }
        let Some(&version) = self.inner.first() else {
            return false;
        };
        let Some(&inverse) = self.inner.get(1) else {
            return false;
        };
        version != DOIP_PROTOCOL_VERSION || inverse != !version
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn try_next_detects_invalid_protocol_version_bytes() {
        let mut buf = FrameBuffer::new(64);
        // version=0x03, inverse=0xFC — does not satisfy `version == 0x02, inverse == 0xFD`
        buf.push(&[0x03, 0xFC, 0x80, 0x01, 0x00, 0x00, 0x00, 0x00]);
        assert!(matches!(buf.try_next(), FrameResult::InvalidHeader));
    }

    #[test]
    fn try_next_returns_incomplete_for_short_buffer() {
        let mut buf = FrameBuffer::new(64);
        buf.push(&[0x02, 0xFD]);
        assert!(matches!(buf.try_next(), FrameResult::Incomplete));
    }

    #[test]
    fn try_next_returns_incomplete_for_empty_buffer() {
        let buf = FrameBuffer::new(64);
        assert!(matches!(buf.try_next(), FrameResult::Incomplete));
    }

    #[test]
    fn try_next_returns_incomplete_when_payload_not_yet_fully_buffered() {
        let mut buf = FrameBuffer::new(64);
        // version=0x02, inverse=0xFD, type=0x8001, payload_length=4 — but no payload bytes
        buf.push(&[0x02, 0xFD, 0x80, 0x01, 0x00, 0x00, 0x00, 0x04]);
        assert!(matches!(buf.try_next(), FrameResult::Incomplete));
    }

    #[test]
    fn skip_byte_on_empty_buffer_does_not_panic() {
        let mut buf = FrameBuffer::new(64);
        buf.skip_byte(); // must not panic
        assert_eq!(buf.len(), 0);
    }

    #[test]
    fn is_overflow_false_for_empty_buffer() {
        let buf = FrameBuffer::new(64);
        assert!(!buf.is_overflow());
    }
}
