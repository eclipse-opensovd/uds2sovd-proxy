// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 The Contributors to Eclipse OpenSOVD (see CONTRIBUTORS)
//
// See the NOTICE file(s) distributed with this work for additional
// information regarding copyright ownership.
//
// This program and the accompanying materials are made available under the
// terms of the Apache License Version 2.0 which is available at
// https://www.apache.org/licenses/LICENSE-2.0

use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

use crate::doip::message::ConnectionId;

/// RAII guard for an accepted session slot.
///
/// Holds the connection's unique ID and a shared reference to the session
/// counter. When dropped (session thread exits, error, or clean close), the
/// counter is automatically decremented - no explicit cleanup required.
pub(in crate::server::tcp) struct ConnectionSlot {
    id: ConnectionId,
    counter: Arc<AtomicUsize>,
}

impl ConnectionSlot {
    pub(super) fn new(id: ConnectionId, counter: Arc<AtomicUsize>) -> Self {
        Self { id, counter }
    }

    /// The unique ID assigned to this connection.
    pub(in crate::server::tcp) fn id(&self) -> &ConnectionId {
        &self.id
    }
}

impl Drop for ConnectionSlot {
    fn drop(&mut self) {
        self.counter.fetch_sub(1, Ordering::SeqCst);
        tracing::debug!(id = %self.id, "session slot released");
    }
}
