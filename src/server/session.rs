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

use parking_lot::RwLock;
use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use tracing::debug;

/// Session states per ISO 13400-2:2019 connection lifecycle
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SessionState {
    Connected,
    RoutingActive,
    Closed,
}

/// A single `DoIP` tester connection and its lifecycle state.
#[derive(Debug, Clone)]
pub struct Session {
    /// Unique monotonic session identifier assigned at connection time
    id: u64,
    /// Remote socket address of the connected tester
    peer_addr: SocketAddr,
    /// Tester logical address registered during routing activation (`0` until activated)
    tester_address: u16,
    /// Current state in the ISO 13400-2 connection lifecycle
    state: SessionState,
}

impl Session {
    /// Create a new session in the [`SessionState::Connected`] state.
    #[must_use]
    pub fn new(id: u64, peer_addr: SocketAddr) -> Self {
        Self {
            id,
            peer_addr,
            tester_address: 0,
            state: SessionState::Connected,
        }
    }

    /// Transition this session to [`SessionState::RoutingActive`] and record the tester's logical address.
    pub fn activate_routing(&mut self, tester_address: u16) {
        debug!(
            "Session {} routing activated: tester_address=0x{:04X}",
            self.id, tester_address
        );
        self.tester_address = tester_address;
        self.state = SessionState::RoutingActive;
    }

    /// Returns `true` if routing has been activated for this session.
    #[must_use]
    pub fn is_routing_active(&self) -> bool {
        self.state == SessionState::RoutingActive
    }

    /// Returns the unique session ID.
    #[must_use]
    pub fn id(&self) -> u64 {
        self.id
    }

    /// Returns the remote socket address of the connected tester.
    #[must_use]
    pub fn peer_addr(&self) -> SocketAddr {
        self.peer_addr
    }

    /// Returns the tester logical address (`0` until routing is activated).
    #[must_use]
    pub fn tester_address(&self) -> u16 {
        self.tester_address
    }

    /// Returns the current lifecycle state.
    #[must_use]
    pub fn state(&self) -> SessionState {
        self.state
    }
}

/// Thread-safe registry of active `DoIP` sessions.
///
/// Internally uses `parking_lot::RwLock` maps keyed by session ID and
/// remote [`SocketAddr`]. Access this via the [`Arc`] returned by
/// [`SessionManager::new`].
#[derive(Debug, Default)]
pub struct SessionManager {
    sessions: RwLock<HashMap<u64, Session>>,
    addr_to_session: RwLock<HashMap<SocketAddr, u64>>,
    next_id: RwLock<u64>,
}

impl SessionManager {
    /// Create a new `SessionManager` wrapped in an [`Arc`] for shared ownership across tasks.
    #[must_use]
    pub fn new() -> Arc<Self> {
        Arc::new(Self::default())
    }

    /// Register a new session for `peer_addr` and return it.
    pub fn create_session(&self, peer_addr: SocketAddr) -> Session {
        let mut next_id = self.next_id.write();
        let id = *next_id;
        *next_id = next_id.saturating_add(1);

        let session = Session::new(id, peer_addr);
        self.sessions.write().insert(id, session.clone());
        self.addr_to_session.write().insert(peer_addr, id);

        debug!("Session {} created for {}", id, peer_addr);
        session
    }

    /// Look up a session by its numeric ID. Returns `None` if not found.
    pub fn get_session(&self, id: u64) -> Option<Session> {
        self.sessions.read().get(&id).cloned()
    }

    /// Look up a session by the tester's remote address. Returns `None` if not found.
    pub fn get_session_by_addr(&self, addr: &SocketAddr) -> Option<Session> {
        let id = self.addr_to_session.read().get(addr).copied()?;
        self.get_session(id)
    }

    /// Apply a mutation `f` to the session with the given `id`. Returns `true` if found.
    pub fn update_session<F>(&self, id: u64, f: F) -> bool
    where
        F: FnOnce(&mut Session),
    {
        if let Some(session) = self.sessions.write().get_mut(&id) {
            f(session);
            true
        } else {
            false
        }
    }

    /// Remove and return the session with the given `id`, or `None` if not found.
    pub fn remove_session(&self, id: u64) -> Option<Session> {
        let session = self.sessions.write().remove(&id)?;
        self.addr_to_session.write().remove(&session.peer_addr);
        debug!("Session {} removed (peer: {})", id, session.peer_addr);
        Some(session)
    }

    /// Remove and return the session associated with `addr`, or `None` if not found.
    pub fn remove_session_by_addr(&self, addr: &SocketAddr) -> Option<Session> {
        let id = self.addr_to_session.write().remove(addr)?;
        let session = self.sessions.write().remove(&id)?;
        debug!("Session {} removed by addr (peer: {})", id, addr);
        Some(session)
    }

    /// Returns the number of currently registered sessions.
    pub fn session_count(&self) -> usize {
        self.sessions.read().len()
    }

    /// Returns `true` if any active session has `tester_address` registered with routing active.
    pub fn is_tester_registered(&self, tester_address: u16) -> bool {
        self.sessions
            .read()
            .values()
            .any(|s| s.tester_address == tester_address && s.state == SessionState::RoutingActive)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn create_and_get_session() {
        let mgr = SessionManager::new();
        let addr: SocketAddr = "127.0.0.1:5000".parse().unwrap();

        let session = mgr.create_session(addr);
        assert_eq!(session.state(), SessionState::Connected);

        let retrieved = mgr.get_session(session.id()).unwrap();
        assert_eq!(retrieved.peer_addr(), addr);
    }

    #[test]
    fn activate_routing() {
        let mgr = SessionManager::new();
        let addr: SocketAddr = "127.0.0.1:5000".parse().unwrap();

        let session = mgr.create_session(addr);
        mgr.update_session(session.id(), |s| s.activate_routing(0x0E80));

        let updated = mgr.get_session(session.id()).unwrap();
        assert!(updated.is_routing_active());
        assert_eq!(updated.tester_address(), 0x0E80);
    }

    #[test]
    fn remove_session() {
        let mgr = SessionManager::new();
        let addr: SocketAddr = "127.0.0.1:5000".parse().unwrap();

        let session = mgr.create_session(addr);
        assert_eq!(mgr.session_count(), 1);

        mgr.remove_session(session.id());
        assert_eq!(mgr.session_count(), 0);
        assert!(mgr.get_session(session.id()).is_none());
    }

    #[test]
    fn check_tester_registered() {
        let mgr = SessionManager::new();
        let addr: SocketAddr = "127.0.0.1:5000".parse().unwrap();

        let session = mgr.create_session(addr);
        assert!(!mgr.is_tester_registered(0x0E80));

        mgr.update_session(session.id(), |s| s.activate_routing(0x0E80));
        assert!(mgr.is_tester_registered(0x0E80));
    }
}
