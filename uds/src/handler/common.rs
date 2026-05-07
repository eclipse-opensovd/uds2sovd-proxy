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

//! Common types shared across all UDS request handlers.
//!
//! This module contains:
//! - [`DataIdentifier`] — the typed 16-bit DID newtype used by all request structs.
//! - [`RequestHandler`] — the visitor trait implemented by every request type.

use std::fmt;

use crate::error::Result;

use super::diag_handler::DiagHandler;

// ── DataIdentifier ────────────────────────────────────────────────────────────

/// A 16-bit UDS Data Identifier (DID), as defined by ISO 14229-1 #11.
///
/// Wrapping the raw `u16` prevents accidental confusion with other 16-bit
/// values such as ECU logical addresses or tester source addresses.
///
/// # Example
///
/// ```rust
/// use uds::DataIdentifier;
/// let did = DataIdentifier::new(0xF190);
/// assert_eq!(did.value(), 0xF190);
/// assert_eq!(format!("{did}"), "0xF190");
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct DataIdentifier(u16);

impl DataIdentifier {
    /// Construct a `DataIdentifier` from a raw 16-bit value.
    #[must_use]
    pub const fn new(did: u16) -> Self {
        Self(did)
    }

    /// Return the raw 16-bit value.
    #[must_use]
    pub const fn value(self) -> u16 {
        self.0
    }
}

impl fmt::Display for DataIdentifier {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "0x{:04X}", self.0)
    }
}

impl From<u16> for DataIdentifier {
    /// Convert a raw `u16` into a typed [`DataIdentifier`].
    ///
    /// ```rust
    /// use uds::DataIdentifier;
    /// let did: DataIdentifier = 0xF190u16.into();
    /// assert_eq!(did.value(), 0xF190);
    /// ```
    fn from(v: u16) -> Self {
        Self(v)
    }
}

// ── RequestHandler ────────────────────────────────────────────────────────────

/// Implemented by UDS request types to drive dispatch into the backend.
///
/// Each request type knows exactly which [`DiagHandler`] method to call —
/// the backend never needs to inspect the request type.  This is the
/// "visitor" half of the visitor pattern: the request visits the backend
/// by calling the appropriate specific method.
#[async_trait::async_trait]
pub trait RequestHandler: Send + Sync {
    /// Dispatch this request to the given backend and return the UDS response.
    ///
    /// # Errors
    ///
    /// Propagates any error returned by the backend.
    async fn handle(&self, backend: &dyn DiagHandler) -> Result<Vec<u8>>;
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    // ── DataIdentifier ────────────────────────────────────────────────────────

    #[test]
    fn data_identifier_new_round_trips() {
        let did = DataIdentifier::new(0xABCD);
        assert_eq!(did.value(), 0xABCD);
    }

    #[test]
    fn data_identifier_display_uses_four_hex_digits() {
        assert_eq!(format!("{}", DataIdentifier::new(0x0001)), "0x0001");
        assert_eq!(format!("{}", DataIdentifier::new(0xFFFF)), "0xFFFF");
        assert_eq!(format!("{}", DataIdentifier::new(0xF190)), "0xF190");
    }

    #[test]
    fn data_identifier_from_u16_round_trips() {
        let did: DataIdentifier = 0xF190u16.into();
        assert_eq!(did.value(), 0xF190);
    }

    #[test]
    fn data_identifier_const_fn_works_in_const_context() {
        const DID: DataIdentifier = DataIdentifier::new(0x1234);
        assert_eq!(DID.value(), 0x1234);
    }

    #[test]
    fn data_identifier_equality_and_hash() {
        use std::collections::HashSet;
        let a = DataIdentifier::new(0xF190);
        let b: DataIdentifier = 0xF190u16.into();
        assert_eq!(a, b);
        let mut set = HashSet::new();
        set.insert(a);
        assert!(set.contains(&b));
    }

    #[test]
    fn data_identifier_debug_contains_value() {
        let s = format!("{:?}", DataIdentifier::new(0xDEAD));
        assert!(s.contains("DataIdentifier"), "debug should include type name");
    }
}
