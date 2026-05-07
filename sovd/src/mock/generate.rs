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

//! Synthetic SOVD response data generation from MDD POS-RESPONSE metadata.
//!
//! Separated from [`super`] so the generation logic and its helpers are
//! independently testable without constructing a full [`super::MockSovdGateway`].

use cda_interfaces::{ParameterTypeMetadata, ResponseParameterInfo};
use serde_json::{Map, Value};
use uds::DataIdentifier;

use crate::resolver::find_mux_case_prefix;

// ── Public-to-crate generation entry point ────────────────────────────────────

/// Build a synthetic SOVD JSON response map from MDD POS-RESPONSE parameter
/// metadata.
///
/// For each VALUE/PhysConst parameter in the response structure, emits a
/// realistic default derived from the ODX parameter definition:
///
/// - **`PhysConst`**: uses the `coded_value` from MDD.
/// - **VALUE with known `byte_size`**: uses a sensible placeholder (small
///   numeric for 1–8 byte fields; zero-filled array for larger fields).
/// - **`CodedConst` / `MatchingRequestParam`**: skipped — the MDD response
///   encoder fills those automatically.
///
/// When the service uses MUX cases, only parameters belonging to the case
/// that matches `did` are included.
pub(super) fn generate_mock_response_data(
    response_meta: &[ResponseParameterInfo],
    did: DataIdentifier,
) -> Map<String, Value> {
    let mux_case_prefix = find_mux_case_prefix(response_meta, did.value());

    // Detect opaque response layouts: a single VALUE param with unknown byte_size.
    let active_value_like: Vec<&ResponseParameterInfo> = response_meta
        .iter()
        .filter(|p| {
            if p.name.starts_with("__mux_case__/") {
                return false;
            }
            if p.name.contains('/') {
                match &mux_case_prefix {
                    Some(prefix) if p.name.starts_with(prefix.as_str()) => {}
                    _ => return false,
                }
            }
            matches!(
                p.param_type,
                ParameterTypeMetadata::Value { .. } | ParameterTypeMetadata::PhysConst { .. }
            )
        })
        .collect();

    let opaque_single_value = active_value_like.len() == 1
        && active_value_like.first().is_some_and(|p| {
            matches!(p.param_type, ParameterTypeMetadata::Value { .. }) && p.byte_size.is_none()
        });

    let mut data = Map::new();
    for p in response_meta {
        if p.name.starts_with("__mux_case__/") {
            continue;
        }
        if p.name.contains('/') {
            match &mux_case_prefix {
                Some(prefix) if p.name.starts_with(prefix.as_str()) => {}
                _ => continue,
            }
        }
        match &p.param_type {
            ParameterTypeMetadata::CodedConst { .. }
            | ParameterTypeMetadata::MatchingRequestParam { .. } => {}
            ParameterTypeMetadata::PhysConst { coded_value, .. } => {
                let key = p.name.rsplit('/').next().unwrap_or(&p.name).to_string();
                let value = coded_value
                    .map(|cv| Value::Number(cv.into()))
                    .unwrap_or_else(|| Value::Number(0.into()));
                data.insert(key, value);
            }
            ParameterTypeMetadata::Value { .. } => {
                let key = p.name.rsplit('/').next().unwrap_or(&p.name).to_string();
                let value = if p.byte_size.is_none() && opaque_single_value {
                    mock_opaque_payload()
                } else {
                    default_value_for_param(p.byte_size)
                };
                data.insert(key, value);
            }
        }
    }

    data
}

// ── Helpers ───────────────────────────────────────────────────────────────────

/// Derive a generic default value for a VALUE parameter based on its byte size.
fn default_value_for_param(byte_size: Option<u32>) -> Value {
    match byte_size {
        Some(sz @ 1..=8) => Value::Number(u64::from(sz).into()),
        Some(sz) => Value::Array(vec![Value::Number(0.into()); sz as usize]),
        None => Value::Number(0.into()),
    }
}

/// Generate a fixed-size opaque byte array for variable-length (END-OF-PDU)
/// parameters whose layout cannot be inferred from metadata alone.
fn mock_opaque_payload() -> Value {
    const DEFAULT_OPAQUE_SIZE: usize = 4;
    Value::Array(vec![Value::Number(0.into()); DEFAULT_OPAQUE_SIZE])
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use cda_interfaces::ParameterTypeMetadata;

    use super::*;

    fn value_param(name: &str, byte_size: Option<u32>) -> ResponseParameterInfo {
        ResponseParameterInfo {
            name: name.to_string(),
            semantic: Some("DATA".to_string()),
            param_type: ParameterTypeMetadata::Value {
                physical_default_value: None,
                coded_default_value: None,
                compu_scales: vec![],
            },
            byte_position: 0,
            bit_position: 0,
            byte_size,
        }
    }

    fn coded_const_param(name: &str) -> ResponseParameterInfo {
        ResponseParameterInfo {
            name: name.to_string(),
            semantic: Some("SERVICE-ID".to_string()),
            param_type: ParameterTypeMetadata::CodedConst { coded_value: "98".to_string() },
            byte_position: 0,
            bit_position: 0,
            byte_size: Some(1),
        }
    }

    fn matching_request_param(name: &str) -> ResponseParameterInfo {
        ResponseParameterInfo {
            name: name.to_string(),
            semantic: Some("DATA-IDENTIFIER".to_string()),
            param_type: ParameterTypeMetadata::MatchingRequestParam { byte_length: 2 },
            byte_position: 1,
            bit_position: 0,
            byte_size: Some(2),
        }
    }

    #[test]
    fn generate_includes_value_params_skips_const() {
        let meta =
            vec![coded_const_param("sid"), matching_request_param("RDBI_DID"), value_param(
                "VALUE_FIELD",
                Some(4),
            )];
        let data = generate_mock_response_data(&meta, 0xF190.into());
        assert!(data.contains_key("VALUE_FIELD"), "VALUE param must be included");
        assert!(!data.contains_key("sid"), "CodedConst must be skipped");
        assert!(!data.contains_key("RDBI_DID"), "MatchingRequestParam must be skipped");
    }

    #[test]
    fn default_value_for_small_byte_size_is_numeric() {
        assert_eq!(default_value_for_param(Some(1)), Value::Number(1.into()));
        assert_eq!(default_value_for_param(Some(4)), Value::Number(4.into()));
        assert_eq!(default_value_for_param(Some(8)), Value::Number(8.into()));
    }

    #[test]
    fn default_value_for_large_byte_size_is_array() {
        let v = default_value_for_param(Some(9));
        assert!(v.is_array());
        assert_eq!(v.as_array().expect("must be array").len(), 9);
    }

    #[test]
    fn mock_opaque_payload_has_fixed_size() {
        let v = mock_opaque_payload();
        assert!(v.is_array());
        assert_eq!(v.as_array().expect("must be array").len(), 4);
    }
}
