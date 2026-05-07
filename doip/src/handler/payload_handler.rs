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

//! `DoIP` payload handler trait and shared immutable connection context.
//!
//! [`PayloadHandler`] is the **extension point** for new `DoIP` payload types.
//! To add support for a new type:
//!
//! 1. Create a zero-size struct (e.g. `pub(super) struct AliveCheckHandler;`).
//! 2. Implement this trait: return `true` from `handles` for the relevant
//!    [`PayloadType`], and produce response frames from `handle`.
//! 3. Register `Box::new(AliveCheckHandler)` in [`ConnectionHandler::new`].
//!
//! **No existing handler code changes.**

use uds::Result;

use crate::{
    config::DoipConnectionConfig,
    message::{DoIpMessage, PayloadType},
    session::Session,
    uds_dispatcher::UdsDispatcher,
};

/// Immutable per-connection context shared with all [`PayloadHandler`] implementations.
///
/// Groups the connection config and UDS dispatcher so that handler
/// implementations receive all read-only state through a single parameter.
pub(crate) struct HandlerContext {
    /// `DoIP` addressing: ECU logical address and tester source address.
    pub(crate) conn_config: DoipConnectionConfig,
    /// UDS SID dispatcher — routes parsed UDS requests to the diagnostic backend.
    pub(crate) dispatcher: UdsDispatcher,
}

/// Extension point for `DoIP` payload type handling.
///
/// Each implementor handles one or more [`PayloadType`] values. The
/// [`ConnectionHandler`](super::ConnectionHandler) iterates its registered
/// handler list and invokes the first that matches the incoming frame's type.
///
/// Implementors **must not** access the TCP stream directly; all output is
/// expressed by returning response frames.  An empty `Vec` means no response
/// (silent drop).
///
/// # Errors
///
/// Return an error only for unrecoverable conditions. Protocol-level invalid
/// inputs (wrong address, bad payload length, unexpected state) should be
/// logged and return `Ok(vec![])`.
#[async_trait::async_trait]
pub(crate) trait PayloadHandler: Send + Sync {
    /// Returns `true` when this handler knows how to process frames of type `pt`.
    fn handles(&self, pt: PayloadType) -> bool;

    /// Process one `DoIP` frame and return zero or more `DoIP` response frames.
    ///
    /// `session` is passed mutably because routing activation writes to it and
    /// diagnostic message handling reads from it. `ctx` provides the
    /// read-only connection config and UDS dispatcher.
    async fn handle(
        &self,
        msg: &DoIpMessage,
        session: &mut Session,
        ctx: &HandlerContext,
    ) -> Result<Vec<DoIpMessage>>;
}
