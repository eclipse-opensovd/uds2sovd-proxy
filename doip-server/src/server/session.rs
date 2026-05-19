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
//! Session management for `DoIP` connections

use std::{
    collections::HashMap,
    net::SocketAddr,
    sync::{
        Arc,
        atomic::{AtomicU64, Ordering},
    },
};

use parking_lot::RwLock;
use tracing::debug;

/// Strongly-typed session identifier — wraps a monotonic `u64` counter.
///
/// Using a newtype prevents accidentally passing a raw integer where a session
/// ID is expected and makes call sites self-documenting.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct SessionId(u64);

/// Session states per ISO 13400-2:2019 connection lifecycle
///
/// This is an internal type. External callers should use [`Session::is_routing_active`] instead.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum SessionState {
    // Used by `TcpConnection` in `feat/tcp-handler` — not yet wired up.
    #[allow(dead_code)]
    Connected,
    RoutingActive,
    /// Reserved per ISO 13400-2:2019 §7.4 lifecycle — not yet transitioned to in-process.
    #[allow(dead_code)]
    Closed,
}

/// A single `DoIP` tester connection and its lifecycle state.
///
/// Tracks the connection lifecycle from initial TCP connect through routing
/// activation to eventual disconnect per ISO 13400-2:2019 §7.4.
#[derive(Debug, Clone)]
pub(crate) struct Session {
    /// Unique monotonic session identifier assigned at connection time
    id: SessionId,
    /// Remote socket address of the connected tester
    peer_addr: SocketAddr,
    /// Tester logical address registered during routing activation (`0` until activated)
    tester_address: u16,
    /// Current state in the ISO 13400-2 connection lifecycle
    state: SessionState,
}

impl Session {
    /// Create a new session in the [`SessionState::Connected`] state.
    ///
    /// This is `pub(crate)` — sessions are only ever constructed by [`SessionManager`].
    // Used by `SessionManager::create_session` in `feat/tcp-handler` — not yet wired up.
    #[allow(dead_code)]
    #[must_use]
    pub(crate) fn new(id: SessionId, peer_addr: SocketAddr) -> Self {
        Self {
            id,
            peer_addr,
            tester_address: 0,
            state: SessionState::Connected,
        }
    }

    /// Transition this session to the `RoutingActive` state and record
    /// the tester's logical address.
    // Used by `TcpConnection` in `feat/tcp-handler` — not yet wired up.
    #[allow(dead_code)]
    pub(crate) fn activate_routing(&mut self, tester_address: u16) {
        debug!(session_id = self.id.0, tester_address, "routing activated");
        self.tester_address = tester_address;
        self.state = SessionState::RoutingActive;
    }

    /// Returns `true` if routing has been activated for this session.
    // Used by `RoutingActivationHandler` in `feat/doip-handler-deps` — not yet wired up.
    #[allow(dead_code)]
    #[must_use]
    pub(crate) fn is_routing_active(&self) -> bool {
        self.state == SessionState::RoutingActive
    }

    /// Returns the unique session ID.
    // Used by `TcpConnection` in `feat/tcp-handler` — not yet wired up.
    #[allow(dead_code)]
    #[must_use]
    pub(crate) fn id(&self) -> SessionId {
        self.id
    }

    /// Returns the remote socket address of the connected tester.
    // Used by `TcpConnection` in `feat/tcp-handler` — not yet wired up.
    #[allow(dead_code)]
    #[must_use]
    pub(crate) fn peer_addr(&self) -> SocketAddr {
        self.peer_addr
    }

    /// Returns the tester logical address (`0` until routing is activated).
    // Used by `AliveCheckHandler` in `feat/doip-handler-deps` — not yet wired up.
    #[allow(dead_code)]
    #[must_use]
    pub(crate) fn tester_address(&self) -> u16 {
        self.tester_address
    }

    /// Returns the current ISO 13400-2 connection lifecycle state.
    ///
    /// This is `pub(crate)` — external callers should use [`is_routing_active`] instead,
    /// which provides a boolean answer without exposing the internal [`SessionState`] type.
    #[must_use]
    #[cfg(test)]
    pub(crate) fn connection_state(&self) -> SessionState {
        self.state
    }
}

/// Thread-safe registry of active `DoIP` sessions.
///
/// The mutable session state is held in this single [`RwLock`]-protected `Inner`
/// struct for atomic multi-map updates, while the monotonic ID counter uses
/// an [`AtomicU64`] to avoid taking the write-lock just to mint a new ID.
/// Access this via the [`Arc`] returned by [`SessionManager::new`].
#[derive(Debug, Default)]
struct SessionManagerInner {
    // Used by `SessionManager` in `feat/tcp-handler` — not yet wired up.
    #[allow(dead_code)]
    sessions: HashMap<SessionId, Session>,
    #[allow(dead_code)]
    addr_to_session: HashMap<SocketAddr, SessionId>,
}

/// Thread-safe registry of active `DoIP` tester sessions.
///
/// Uses a single [`RwLock`] over an internal map to ensure atomic consistency
/// between the session map and the address-to-ID index, plus a lock-free
/// [`AtomicU64`] counter for session ID allocation.
#[derive(Debug, Default)]
pub struct SessionManager {
    // Used by `TcpConnection` in `feat/tcp-handler` — not yet wired up.
    #[allow(dead_code)]
    inner: RwLock<SessionManagerInner>,
    #[allow(dead_code)]
    next_id: AtomicU64,
}

impl SessionManager {
    /// Create a new `SessionManager` wrapped in an [`Arc`] for shared ownership across tasks.
    #[must_use]
    pub fn new() -> Arc<Self> {
        Arc::new(Self::default())
    }

    /// Register a new session for `peer_addr` and return it.
    // Used by `TcpConnection` in `feat/tcp-handler` — not yet wired up.
    #[allow(dead_code)]
    pub(crate) fn create_session(&self, peer_addr: SocketAddr) -> Session {
        let id = SessionId(self.next_id.fetch_add(1, Ordering::Relaxed));
        let session = Session::new(id, peer_addr);
        {
            let mut inner = self.inner.write();
            inner.sessions.insert(id, session.clone());
            inner.addr_to_session.insert(peer_addr, id);
        }
        debug!(session_id = id.0, peer = %peer_addr, "Session created");
        session
    }

    /// Look up a session by its numeric ID. Returns `None` if not found.
    // Used by `TcpConnection` in `feat/tcp-handler` — not yet wired up.
    #[allow(dead_code)]
    pub(crate) fn get_session(&self, id: SessionId) -> Option<Session> {
        self.inner.read().sessions.get(&id).cloned()
    }

    /// Look up a session by the tester's remote address. Returns `None` if not found.
    // Used by `TcpConnection` in `feat/tcp-handler` — not yet wired up.
    #[allow(dead_code)]
    pub(crate) fn get_session_by_addr(&self, addr: &SocketAddr) -> Option<Session> {
        let inner = self.inner.read();
        let id = inner.addr_to_session.get(addr).copied()?;
        inner.sessions.get(&id).cloned()
    }

    /// Apply a mutation `f` to the session with the given `id`. Returns `true` if found.
    // Used by `TcpConnection` in `feat/tcp-handler` — not yet wired up.
    #[allow(dead_code)]
    pub(crate) fn update_session<F>(&self, id: SessionId, f: F) -> bool
    where
        F: FnOnce(&mut Session),
    {
        self.inner
            .write()
            .sessions
            .get_mut(&id)
            .is_some_and(|session| {
                f(session);
                true
            })
    }

    /// Remove and return the session with the given `id`, or `None` if not found.
    // Used by `TcpConnection` in `feat/tcp-handler` — not yet wired up.
    #[allow(dead_code)]
    pub(crate) fn remove_session(&self, id: SessionId) -> Option<Session> {
        let session = {
            let mut inner = self.inner.write();
            let session = inner.sessions.remove(&id)?;
            inner.addr_to_session.remove(&session.peer_addr);
            session
        };
        debug!(session_id = id.0, peer = %session.peer_addr, "Session removed");
        Some(session)
    }

    /// Remove and return the session associated with `addr`, or `None` if not found.
    // Used by `TcpConnection` in `feat/tcp-handler` — not yet wired up.
    #[allow(dead_code)]
    pub(crate) fn remove_session_by_addr(&self, addr: &SocketAddr) -> Option<Session> {
        let session = {
            let mut inner = self.inner.write();
            let id = inner.addr_to_session.remove(addr)?;
            inner.sessions.remove(&id)?
        };
        debug!(session_id = session.id.0, peer = %addr, "Session removed by addr");
        Some(session)
    }

    /// Returns the number of currently registered sessions.
    pub fn session_count(&self) -> usize {
        self.inner.read().sessions.len()
    }

    /// Returns `true` if any active session has `tester_address` registered with routing active.
    pub fn is_tester_registered(&self, tester_address: u16) -> bool {
        self.inner
            .read()
            .sessions
            .values()
            .any(|s| s.tester_address == tester_address && s.state == SessionState::RoutingActive)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn session_is_created_in_connected_state() {
        let mgr = SessionManager::new();
        let addr: SocketAddr = "127.0.0.1:5000".parse().unwrap();

        let session = mgr.create_session(addr);
        // New sessions must start in Connected state per ISO 13400-2 lifecycle
        assert_eq!(session.connection_state(), SessionState::Connected);

        let retrieved = mgr.get_session(session.id()).unwrap();
        assert_eq!(retrieved.peer_addr(), addr);
    }

    #[test]
    fn session_transitions_to_routing_active() {
        let mgr = SessionManager::new();
        let addr: SocketAddr = "127.0.0.1:5000".parse().unwrap();

        let session = mgr.create_session(addr);
        mgr.update_session(session.id(), |s| s.activate_routing(0x0E80));

        let updated = mgr.get_session(session.id()).unwrap();
        // After routing activation the session must be RoutingActive
        // and the tester logical address must be recorded
        assert!(updated.is_routing_active());
        assert_eq!(updated.tester_address(), 0x0E80);
    }

    #[test]
    fn session_is_removed_from_registry() {
        let mgr = SessionManager::new();
        let addr: SocketAddr = "127.0.0.1:5000".parse().unwrap();

        let session = mgr.create_session(addr);
        assert_eq!(mgr.session_count(), 1);

        mgr.remove_session(session.id());
        // Both the session map and addr index must be cleaned up
        assert_eq!(mgr.session_count(), 0);
        assert!(mgr.get_session(session.id()).is_none());
    }

    #[test]
    fn tester_is_registered_only_after_routing_activation() {
        let mgr = SessionManager::new();
        let addr: SocketAddr = "127.0.0.1:5000".parse().unwrap();

        let session = mgr.create_session(addr);
        // Before activation: tester address must not be registered
        assert!(!mgr.is_tester_registered(0x0E80));

        mgr.update_session(session.id(), |s| s.activate_routing(0x0E80));
        // After activation: tester address must be found in the registry
        assert!(mgr.is_tester_registered(0x0E80));
    }
}
