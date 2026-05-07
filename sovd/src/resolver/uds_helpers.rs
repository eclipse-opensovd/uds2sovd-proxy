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

//! CDA factory helpers.
//!
//! Thin wrappers that construct CDA request/response types used by the
//! resolver sub-modules.  All functions here have a direct CDA dependency
//! and are confined to the `resolver/` boundary.

use cda_interfaces::{DiagComm, DiagCommType, ServicePayload};

/// Map a UDS SID to its [`DiagCommType`].
///
/// Falls back to [`DiagCommType::Data`] for unrecognised SIDs so that the
/// caller always receives a usable type rather than an error.
pub(super) fn diag_comm_type(service_id: u8) -> DiagCommType {
    DiagCommType::try_from(service_id).unwrap_or(DiagCommType::Data)
}

/// Create a `ServicePayload` from raw UDS bytes with default addresses.
pub(super) fn make_service_payload(data: &[u8]) -> ServicePayload {
    ServicePayload {
        data: data.to_vec(),
        source_address: 0,
        target_address: 0,
        new_session: None,
        new_security: None,
    }
}

/// Create a [`DiagComm`] for the given service name and UDS service identifier.
///
/// Centralises the repeated inline construction so that callers never have to
/// name [`DiagComm`] directly.  Both `name` and `lookup_name` are set to the
/// same value, which is what the CDA requires for service dispatch.
pub(super) fn make_diag_comm(service_name: &str, service_id: u8) -> DiagComm {
    let name = service_name.to_string();
    DiagComm {
        lookup_name: Some(name.clone()),
        name,
        type_: diag_comm_type(service_id),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn make_service_payload_copies_bytes_and_defaults_addresses() {
        let data = &[0x62, 0xF1, 0x90, 0x57];
        let payload = make_service_payload(data);
        assert_eq!(payload.data, vec![0x62, 0xF1, 0x90, 0x57]);
        assert_eq!(payload.source_address, 0);
        assert_eq!(payload.target_address, 0);
        assert!(payload.new_session.is_none());
        assert!(payload.new_security.is_none());
    }
}
