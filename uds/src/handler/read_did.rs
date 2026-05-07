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

//! `ReadDataByIdentifier` (SID 0x22) request type and its [`RequestHandler`] impl.

use crate::error::Result;

use super::{
    common::{DataIdentifier, RequestHandler},
    diag_handler::DiagHandler,
};

// ── ReadDid ───────────────────────────────────────────────────────────────────

/// A `ReadDataByIdentifier` (SID 0x22) request.
///
/// Carries the DID as a typed [`DataIdentifier`] and the full raw UDS bytes
/// (SID included) so the backend can inspect or forward the original payload.
///
/// # Example
///
/// ```rust
/// use uds::{DataIdentifier, ReadDid};
/// let req = ReadDid {
///     did: DataIdentifier::new(0xF190),
///     raw: vec![0x22, 0xF1, 0x90],
/// };
/// assert_eq!(req.did.value(), 0xF190);
/// assert_eq!(req.raw[0], 0x22);
/// ```
#[derive(Debug, Clone)]
pub struct ReadDid {
    /// Typed 16-bit Data Identifier extracted from the request.
    pub did: DataIdentifier,
    /// Full raw UDS request bytes: `[0x22, DID_HI, DID_LO]`.
    pub raw: Vec<u8>,
}

#[async_trait::async_trait]
impl RequestHandler for ReadDid {
    async fn handle(&self, backend: &dyn DiagHandler) -> Result<Vec<u8>> {
        backend.read_did(self).await
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn read_did_fields_accessible() {
        let req = ReadDid { did: DataIdentifier::new(0xF190), raw: vec![0x22, 0xF1, 0x90] };
        assert_eq!(req.did.value(), 0xF190);
        assert_eq!(req.raw.first().copied(), Some(0x22));
    }

    #[test]
    fn read_did_clone_is_independent() {
        let req = ReadDid { did: DataIdentifier::new(0x1000), raw: vec![0x22, 0x10, 0x00] };
        let mut clone = req.clone();
        clone.raw.push(0xFF);
        assert_eq!(req.raw.len(), 3, "original must not be modified");
    }
}
