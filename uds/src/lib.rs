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

//! Core UDS protocol primitives for the UDS-to-SOVD proxy.
//!
//! This crate is the **zero-dependency seam** between the `DoIP` transport
//! layer ([`doip`]) and the SOVD integration layer ([`sovd`]).  It contains
//! only:
//!
//! - [`error`] — shared error types ([`ProxyError`], [`error::UdsError`],
//!   [`error::SovdError`], [`error::Nrc`]).
//! - [`handler`] — the [`DiagHandler`] async trait that decouples transport
//!   from backend.
//! - [`uds_service_ids`] — ISO 14229-1 Service Identifier constants.
//!
//! # Dependency rule
//!
//! `uds` must **never** depend on `cda-*`, `reqwest`, `tokio`, or any
//! other heavy runtime crate.  Keep it lean so that the `doip` crate can use
//! it without pulling in the MDD resolver or the SOVD HTTP stack.

pub mod error;
pub mod handler;
pub mod uds_service_ids;

pub use error::{Nrc, ProxyError, Result};
pub use handler::{DataIdentifier, DiagHandler, ReadDid, RequestHandler, UdsRequest, WriteDid};
pub use uds_service_ids::UdsSid;

// ── Test-utility macros ───────────────────────────────────────────────────────

/// Assert that a raw UDS response slice is a well-formed negative response
/// for the given `(request_sid, nrc_byte)` pair.
///
/// # Note
///
/// This macro is intended exclusively for use in `#[cfg(test)]` contexts.
/// It is exported at the crate level so that sibling workspace crates (e.g.
/// `doip`) can use it in their own test modules without duplicating the assertion
/// logic. Do not call it from production code.
///
/// Checks:
/// - `response[0] == 0x7F` (negative response SID)
/// - `response[1] == request_sid`
/// - `response[2] == nrc_byte`
///
/// # Example
///
/// ```rust
/// use uds::assert_nrc;
/// let frame = [0x7F, 0x22, 0x11];
/// assert_nrc!(frame, 0x22, 0x11);
/// ```
#[macro_export]
macro_rules! assert_nrc {
    ($response:expr, $sid:expr, $nrc:expr) => {{
        let resp = &$response;
        assert_eq!(
            resp.first().copied(),
            Some(0x7Fu8),
            "expected NRC frame — first byte must be 0x7F, got {:02X?}",
            resp.first()
        );
        assert_eq!(
            resp.get(1).copied(),
            Some($sid as u8),
            "NRC must echo request SID 0x{:02X}, got {:02X?}",
            $sid as u8,
            resp.get(1)
        );
        assert_eq!(
            resp.get(2).copied(),
            Some($nrc as u8),
            "NRC code must be 0x{:02X}, got {:02X?}",
            $nrc as u8,
            resp.get(2)
        );
    }};
}

/// Assert that a raw UDS response slice is a positive response for the given
/// `(response_sid, did_hi, did_lo)` tuple.
///
/// Checks:
/// - `response[0] == response_sid`  (e.g. `0x62` for RDBI, `0x6E` for WDBI)
/// - `response[1..3] == [did_hi, did_lo]`
///
/// # Example
///
/// ```rust
/// use uds::assert_positive_response;
/// let frame = [0x62u8, 0xF1, 0x90, 0xAB];
/// assert_positive_response!(frame, 0x62, 0xF1, 0x90);
/// ```
#[macro_export]
macro_rules! assert_positive_response {
    ($response:expr, $pos_sid:expr, $did_hi:expr, $did_lo:expr) => {{
        let resp = &$response;
        assert_eq!(
            resp.first().copied(),
            Some($pos_sid as u8),
            "expected positive response SID 0x{:02X}, got {:02X?}",
            $pos_sid as u8,
            resp.first()
        );
        assert_eq!(
            resp.get(1).copied(),
            Some($did_hi as u8),
            "expected DID high byte 0x{:02X}, got {:02X?}",
            $did_hi as u8,
            resp.get(1)
        );
        assert_eq!(
            resp.get(2).copied(),
            Some($did_lo as u8),
            "expected DID low byte 0x{:02X}, got {:02X?}",
            $did_lo as u8,
            resp.get(2)
        );
    }};
}

#[cfg(test)]
mod macro_tests {
    #[test]
    fn assert_nrc_passes_on_valid_frame() {
        let frame = [0x7Fu8, 0x22, 0x11];
        assert_nrc!(frame, 0x22, 0x11);
    }

    #[test]
    fn assert_positive_response_passes_on_valid_frame() {
        let frame = [0x62u8, 0xF1, 0x90, 0xAB, 0xCD];
        assert_positive_response!(frame, 0x62, 0xF1, 0x90);
    }
}
