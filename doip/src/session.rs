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

//! Per-connection `DoIP` routing-activation state machine.
//!
//! [`Session`] wraps [`SessionState`] and exposes transition methods that
//! enforce the correct state machine progression (unactivated → activated).

/// Lifecycle state of a single `DoIP` TCP connection.
///
/// Models the ISO 13400-2 connection lifecycle as a state machine.
/// Using an enum makes impossible states unrepresentable: a session
/// cannot be simultaneously activated and without a tester address.
///
/// ```text
/// [TCP connect] --> Inactive --[RoutingActivationRequest]--> Active { source_address }
///                    |                                            |
///                    +--------[TCP close / clear()]---------------+
///                                        |
///                                   (back to Inactive)
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SessionState {
    /// TCP connection established; routing activation not yet completed.
    Inactive,
    /// Routing activation completed; `source_address` is the tester's logical address.
    Active {
        /// Tester logical source address recorded during routing activation.
        source_address: u16,
    },
}

/// Per-connection `DoIP` session.
///
/// Wraps [`SessionState`] and exposes transition methods that enforce the
/// correct state machine. Callers that only need predicate checks
/// (`is_activated`, `is_activated_for`) do not need to match on the enum
/// directly; callers that need the full state can call [`Session::state`].
pub struct Session {
    state: SessionState,
}

impl Session {
    /// Create a new session in the [`SessionState::Inactive`] state.
    #[must_use]
    pub fn new() -> Self {
        Self {
            state: SessionState::Inactive,
        }
    }

    /// Transition to [`SessionState::Active`] with `source_address` as the
    /// tester's logical address.
    ///
    /// Calling this on an already-active session overwrites the previous
    /// source address (re-activation).
    pub fn activate(&mut self, source_address: u16) {
        self.state = SessionState::Active { source_address };
    }

    /// Returns `true` if the session is in the [`SessionState::Active`] state.
    #[must_use]
    pub fn is_activated(&self) -> bool {
        matches!(self.state, SessionState::Active { .. })
    }

    /// Returns `true` if the session is active **and** was activated for the
    /// given `source_address`.
    #[must_use]
    pub fn is_activated_for(&self, source_address: u16) -> bool {
        matches!(self.state, SessionState::Active { source_address: sa } if sa == source_address)
    }

    /// Returns the tester source address when the session is active, or `None`
    /// when it is in the [`SessionState::Inactive`] state.
    #[must_use]
    pub fn source_address(&self) -> Option<u16> {
        match self.state {
            SessionState::Active { source_address } => Some(source_address),
            SessionState::Inactive => None,
        }
    }

    /// Return a reference to the current [`SessionState`].
    #[must_use]
    pub fn state(&self) -> &SessionState {
        &self.state
    }

    /// Reset the session to [`SessionState::Inactive`].
    pub fn clear(&mut self) {
        self.state = SessionState::Inactive;
    }
}

impl Default for Session {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // ── construction ────────────────────────────────────────────────────────

    #[test]
    fn new_session_is_inactive() {
        let session = Session::new();
        assert!(!session.is_activated());
        assert_eq!(session.source_address(), None);
        assert_eq!(session.state(), &SessionState::Inactive);
    }

    #[test]
    fn default_session_is_inactive() {
        let session = Session::default();
        assert!(!session.is_activated());
        assert_eq!(session.state(), &SessionState::Inactive);
    }

    // ── activation ──────────────────────────────────────────────────────────

    #[test]
    fn activate_transitions_to_active_state() {
        let mut session = Session::new();
        session.activate(0x0E80);

        assert!(session.is_activated());
        assert_eq!(
            session.state(),
            &SessionState::Active {
                source_address: 0x0E80
            }
        );
    }

    #[test]
    fn activate_records_correct_source_address() {
        let mut session = Session::new();
        session.activate(0x0E80);

        assert_eq!(session.source_address(), Some(0x0E80));
    }

    #[test]
    fn is_activated_for_returns_true_for_matching_address() {
        let mut session = Session::new();
        session.activate(0x0E80);

        assert!(session.is_activated_for(0x0E80));
    }

    #[test]
    fn is_activated_for_returns_false_for_wrong_address() {
        let mut session = Session::new();
        session.activate(0x0E80);

        assert!(!session.is_activated_for(0x0E81));
        assert!(!session.is_activated_for(0x0000));
        assert!(!session.is_activated_for(0xFFFF));
    }

    #[test]
    fn is_activated_for_returns_false_when_inactive() {
        let session = Session::new();
        assert!(!session.is_activated_for(0x0E80));
    }

    #[test]
    fn reactivation_overwrites_previous_source_address() {
        let mut session = Session::new();
        session.activate(0x0E80);
        session.activate(0x0001);

        assert!(session.is_activated_for(0x0001));
        assert!(!session.is_activated_for(0x0E80));
        assert_eq!(session.source_address(), Some(0x0001));
    }

    // ── clear / reset ────────────────────────────────────────────────────────

    #[test]
    fn clear_resets_active_session_to_inactive() {
        let mut session = Session::new();
        session.activate(0x0E80);
        session.clear();

        assert!(!session.is_activated());
        assert_eq!(session.source_address(), None);
        assert_eq!(session.state(), &SessionState::Inactive);
    }

    #[test]
    fn clear_on_inactive_session_is_idempotent() {
        let mut session = Session::new();
        session.clear(); // no panic, no state change

        assert!(!session.is_activated());
        assert_eq!(session.state(), &SessionState::Inactive);
    }
}
