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

//! Async diagnostic handler abstraction.
//!
//! # Design: request types drive dispatch (visitor pattern)
//!
//! Each UDS service is a **typed request struct** (`ReadDid`, `WriteDid`, …)
//! that implements [`RequestHandler`].  The single method
//! `RequestHandler::handle(&self, backend: &dyn DiagHandler)` calls the
//! matching method on the backend directly — no `match` is needed in any
//! backend implementation.
//!
//! ```text
//! UdsDispatcher                 RequestHandler        DiagHandler
//!      │                             │                     │
//!      │  ReadDid { did, raw }       │                     │
//!      │──────────────────►ReadDid::handle() ─────────►read_did(req)
//!      │                             │                     │
//!      │  WriteDid { did, raw }      │                     │
//!      │──────────────────►WriteDid::handle() ────────►write_did(req)
//! ```
//!
//! [`UdsRequest`] is a **closed enum** whose `#[non_exhaustive]` attribute
//! means adding a new variant is a compile-time breaking change for every
//! `match` in the codebase.  The **one** match lives inside
//! `impl RequestHandler for UdsRequest` — it is the **explicit, auditable
//! dispatch table** for all supported UDS services.  No other code ever
//! matches on request type.
//!
//! # Why an enum and not `Box<dyn RequestHandler>`?
//!
//! An open `Box<dyn RequestHandler>` eliminates every `match` but loses the
//! compile-time guarantee that every `DiagHandler` implementor handles every
//! service that might arrive at runtime.  For this safety-critical codebase
//! with a known, finite set of UDS services, exhaustiveness is more valuable
//! than zero-match purity.
//!
//! # Extending with new UDS services
//!
//! 1. Add a new request struct in its own `<service>.rs` file (e.g. `session_control.rs`).
//! 2. `impl RequestHandler for SessionControl` — call `backend.session_control(self)`.
//! 3. Add `async fn session_control(&self, req: &SessionControl) -> Result<Vec<u8>>` to
//!    [`DiagHandler`] in `diag_handler.rs`.  The compiler flags every implementor.
//! 4. Add `SessionControl(SessionControl)` variant to [`UdsRequest`] here.
//!    The compiler flags the one match in `impl RequestHandler for UdsRequest`.
//! 5. Add a SID arm in `UdsDispatcher::dispatch()` in the `doip` crate.

pub mod common;
pub mod diag_handler;
pub mod read_did;
pub mod write_did;

pub use common::{DataIdentifier, RequestHandler};
pub use diag_handler::DiagHandler;
pub use read_did::ReadDid;
pub use write_did::WriteDid;

use crate::error::Result;

// ── UdsRequest ────────────────────────────────────────────────────────────────

/// The closed set of all UDS services supported by this proxy.
///
/// Each variant wraps the concrete typed request struct for that service.
/// The enum is `#[non_exhaustive]` so adding a variant is a compile-time
/// breaking change — the compiler flags every `match` site to be updated.
///
/// The **one** match on this enum lives in `impl RequestHandler for UdsRequest`
/// below — the auditable dispatch table.  No `DiagHandler` implementation
/// ever matches on `UdsRequest`; they receive fully-typed request structs
/// through per-service trait methods.
///
/// # Example
///
/// ```rust,no_run
/// use uds::{DataIdentifier, ReadDid, UdsRequest};
/// // Build a request via the enum wrapper:
/// let req = UdsRequest::ReadDid(ReadDid {
///     did: DataIdentifier::new(0xF190),
///     raw: vec![0x22, 0xF1, 0x90],
/// });
/// // `handle()` dispatches to the correct DiagHandler method:
/// // req.handle(&*my_backend).await
/// ```
#[non_exhaustive]
#[derive(Debug, Clone)]
pub enum UdsRequest {
    /// `ReadDataByIdentifier` (SID 0x22).
    ReadDid(ReadDid),
    /// `WriteDataByIdentifier` (SID 0x2E).
    WriteDid(WriteDid),
}

#[async_trait::async_trait]
impl RequestHandler for UdsRequest {
    /// Dispatch to the inner request type — the **single, centralized match**
    /// for all UDS service routing.  No other code in the codebase matches
    /// on request type.
    async fn handle(&self, backend: &dyn DiagHandler) -> Result<Vec<u8>> {
        match self {
            Self::ReadDid(r) => r.handle(backend).await,
            Self::WriteDid(w) => w.handle(backend).await,
        }
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use super::*;
    use crate::error::UdsError;

    // ── Minimal in-process DiagHandler for dispatch tests ────────────────────

    struct SpyHandler {
        reads: std::sync::atomic::AtomicU32,
        writes: std::sync::atomic::AtomicU32,
    }

    impl SpyHandler {
        fn new() -> Self {
            Self {
                reads: std::sync::atomic::AtomicU32::new(0),
                writes: std::sync::atomic::AtomicU32::new(0),
            }
        }

        fn read_count(&self) -> u32 {
            self.reads.load(std::sync::atomic::Ordering::SeqCst)
        }

        fn write_count(&self) -> u32 {
            self.writes.load(std::sync::atomic::Ordering::SeqCst)
        }
    }

    #[async_trait::async_trait]
    impl DiagHandler for SpyHandler {
        async fn read_did(&self, req: &ReadDid) -> Result<Vec<u8>> {
            self.reads.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            Ok(vec![0x62, (req.did.value() >> 8) as u8, (req.did.value() & 0xFF) as u8])
        }

        async fn write_did(&self, req: &WriteDid) -> Result<Vec<u8>> {
            self.writes.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            Ok(vec![0x6E, (req.did.value() >> 8) as u8, (req.did.value() & 0xFF) as u8])
        }
    }

    fn spy() -> Arc<SpyHandler> {
        Arc::new(SpyHandler::new())
    }

    // ── RequestHandler / visitor dispatch ────────────────────────────────────

    #[tokio::test]
    async fn read_did_handle_calls_backend_read_did() {
        let backend = spy();
        let req = ReadDid { did: DataIdentifier::new(0xF190), raw: vec![0x22, 0xF1, 0x90] };
        let resp = req.handle(backend.as_ref()).await.unwrap();
        assert_eq!(resp.first().copied(), Some(0x62u8), "positive RDBI SID");
        assert_eq!(backend.read_count(), 1);
        assert_eq!(backend.write_count(), 0);
    }

    #[tokio::test]
    async fn write_did_handle_calls_backend_write_did() {
        let backend = spy();
        let req =
            WriteDid { did: DataIdentifier::new(0xF190), raw: vec![0x2E, 0xF1, 0x90, 0x01] };
        let resp = req.handle(backend.as_ref()).await.unwrap();
        assert_eq!(resp.first().copied(), Some(0x6Eu8), "positive WDBI SID");
        assert_eq!(backend.read_count(), 0);
        assert_eq!(backend.write_count(), 1);
    }

    #[tokio::test]
    async fn uds_request_read_did_dispatches_to_read_did_method() {
        let backend = spy();
        let req = UdsRequest::ReadDid(ReadDid {
            did: DataIdentifier::new(0xF190),
            raw: vec![0x22, 0xF1, 0x90],
        });
        req.handle(backend.as_ref()).await.unwrap();
        assert_eq!(backend.read_count(), 1);
        assert_eq!(backend.write_count(), 0);
    }

    #[tokio::test]
    async fn uds_request_write_did_dispatches_to_write_did_method() {
        let backend = spy();
        let req = UdsRequest::WriteDid(WriteDid {
            did: DataIdentifier::new(0xF190),
            raw: vec![0x2E, 0xF1, 0x90, 0x00],
        });
        req.handle(backend.as_ref()).await.unwrap();
        assert_eq!(backend.read_count(), 0);
        assert_eq!(backend.write_count(), 1);
    }

    /// Confirm backend errors propagate through `RequestHandler::handle`.
    #[tokio::test]
    async fn request_handler_propagates_backend_error() {
        struct AlwaysErrorHandler;

        #[async_trait::async_trait]
        impl DiagHandler for AlwaysErrorHandler {
            async fn read_did(&self, _req: &ReadDid) -> Result<Vec<u8>> {
                Err(UdsError::InvalidDid(0xDEAD).into())
            }

            async fn write_did(&self, _req: &WriteDid) -> Result<Vec<u8>> {
                Err(UdsError::InvalidDid(0xBEEF).into())
            }
        }

        let backend = AlwaysErrorHandler;
        let req = ReadDid { did: DataIdentifier::new(0xDEAD), raw: vec![0x22, 0xDE, 0xAD] };
        let err = req.handle(&backend).await.unwrap_err();
        assert!(err.to_string().contains("0xdead"), "error must mention the DID");
    }

    /// Confirm that `UdsRequest` clones produce independent copies.
    #[test]
    fn uds_request_clone_is_independent() {
        let req = UdsRequest::ReadDid(ReadDid {
            did: DataIdentifier::new(0xF190),
            raw: vec![0x22, 0xF1, 0x90],
        });
        let clone = req.clone();
        if let (UdsRequest::ReadDid(a), UdsRequest::ReadDid(b)) = (&req, &clone) {
            assert_eq!(a.did, b.did);
        } else {
            panic!("clone must preserve variant");
        }
    }
}
