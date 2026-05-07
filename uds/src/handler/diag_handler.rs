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

//! [`DiagHandler`] — the async backend trait implemented by the SOVD layer and mocks.

use crate::error::Result;

use super::read_did::ReadDid;
use super::write_did::WriteDid;

// ── DiagHandler ───────────────────────────────────────────────────────────────

/// Backend trait implemented by the SOVD layer (and mocks in tests).
///
/// Each method corresponds to exactly one UDS service.  The DoIP transport
/// layer holds an `Arc<dyn DiagHandler>` and passes typed request values —
/// no variant matching is needed in any implementation.
///
/// # Object safety
///
/// The trait is made object-safe via the [`async_trait`] macro, which rewrites
/// each `async fn` as a method returning `Pin<Box<dyn Future>>`.
///
/// # Extending with new services
///
/// Add a new method here, implement [`super::common::RequestHandler`] for the new request
/// struct to call it, and the compiler will flag every `DiagHandler`
/// implementor to add the new method.
#[async_trait::async_trait]
pub trait DiagHandler: Send + Sync {
    /// Handle a `ReadDataByIdentifier` (SID 0x22) request.
    ///
    /// Returns the complete UDS response bytes (positive or negative),
    /// ready to be wrapped in a DoIP diagnostic message payload.
    ///
    /// # Errors
    ///
    /// Returns [`crate::error::ProxyError`] for unrecoverable backend
    /// failures (e.g. no MDD database loaded, I/O failure).  Protocol-level
    /// errors (unknown DID, schema mismatch) must be encoded as UDS negative
    /// responses and returned as `Ok`.
    async fn read_did(&self, req: &ReadDid) -> Result<Vec<u8>>;

    /// Handle a `WriteDataByIdentifier` (SID 0x2E) request.
    ///
    /// Returns the complete UDS response bytes (positive or negative).
    ///
    /// # Errors
    ///
    /// Returns [`crate::error::ProxyError`] for unrecoverable backend
    /// failures.  Protocol-level errors must be encoded as UDS negative
    /// responses and returned as `Ok`.
    async fn write_did(&self, req: &WriteDid) -> Result<Vec<u8>>;
}
