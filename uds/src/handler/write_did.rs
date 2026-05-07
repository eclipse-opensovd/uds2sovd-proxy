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

//! `WriteDataByIdentifier` (SID 0x2E) request type and its [`RequestHandler`] impl.

use crate::error::Result;

use super::{
    common::{DataIdentifier, RequestHandler},
    diag_handler::DiagHandler,
};

// ── WriteDid ──────────────────────────────────────────────────────────────────

/// A `WriteDataByIdentifier` (SID 0x2E) request.
///
/// Carries the DID as a typed [`DataIdentifier`] and the full raw UDS bytes
/// (SID included) including any data bytes following the DID.
///
/// # Example
///
/// ```rust
/// use uds::{DataIdentifier, WriteDid};
/// let req = WriteDid {
///     did: DataIdentifier::new(0xF190),
///     raw: vec![0x2E, 0xF1, 0x90, 0xAB, 0xCD],
/// };
/// // Data payload starts at index 3 (after SID + DID_HI + DID_LO).
/// assert_eq!(&req.raw[3..], &[0xAB, 0xCD]);
/// ```
#[derive(Debug, Clone)]
pub struct WriteDid {
    /// Typed 16-bit Data Identifier extracted from the request.
    pub did: DataIdentifier,
    /// Full raw UDS request bytes: `[0x2E, DID_HI, DID_LO, data…]`.
    pub raw: Vec<u8>,
}

#[async_trait::async_trait]
impl RequestHandler for WriteDid {
    async fn handle(&self, backend: &dyn DiagHandler) -> Result<Vec<u8>> {
        backend.write_did(self).await
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn write_did_data_payload_starts_at_index_three() {
        let req = WriteDid {
            did: DataIdentifier::new(0xF190),
            raw: vec![0x2E, 0xF1, 0x90, 0xAB, 0xCD],
        };
        assert_eq!(req.raw.get(3..), Some([0xAB, 0xCD].as_slice()));
    }
}
