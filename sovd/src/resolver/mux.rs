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

//! MUX-case matching helpers.
//!
//! Floor-based and exact MUX-case lookups for MDD response parameter metadata.

use cda_interfaces::ResponseParameterInfo;

/// Parse a MUX case `coded_value` string as a numeric DID value.
///
/// MDD stores MUX case limits as strings that may be float-formatted
/// (e.g. `"61699.0"`) or integer-formatted (e.g. `"61699"`).
#[must_use]
pub(super) fn parse_mux_coded_value(coded_value: &str) -> Option<u64> {
    let trimmed = coded_value.trim();
    // Try integer parsing first; fall back to float (MDD may store values like "61699.0").
    // The bounds check (`>= 0.0` and `<= u64::MAX as f64`) ensures the value fits before
    // the narrowing cast.  DIDs are 16-bit so precision loss from f64 never occurs in practice.
    #[allow(
        clippy::cast_precision_loss,      // u64::MAX as f64 is safe for the upper-bound comparison
        clippy::cast_possible_truncation, // guarded by the bounds check above
        clippy::cast_sign_loss            // guarded by the `>= 0.0` check above
    )]
    trimmed.parse::<u64>().ok().or_else(|| {
        let v = trimmed.parse::<f64>().ok()?;
        (v >= 0.0 && v <= u64::MAX as f64).then_some(v as u64)
    })
}

/// Find the MUX case prefix that covers a given DID in response metadata.
///
/// MDD `__mux_case__` entries store only the **`lower_limit`** of their range
/// (e.g. a case with `coded_value: "61697"` covering DIDs 0xF101
/// through 0xF140).  A DID like 0xF103 (61699) has no exact match
/// but falls in that range.
///
/// This function uses **floor-based matching**: collect all `__mux_case__`
/// lower bounds, sort them, and find the case with the largest lower bound
/// that does not exceed the DID.  This correctly handles both single-value
/// MUX cases (e.g. 0x7007) and range cases (e.g. 0xD100–0xD150).
#[must_use]
pub fn find_mux_case_prefix(meta: &[ResponseParameterInfo], did: u16) -> Option<String> {
    let did_val = u64::from(did);

    // Collect (lower_bound, case_name) for all MUX case entries.
    let mut mux_entries: Vec<(u64, &str)> = meta
        .iter()
        .filter_map(|p| {
            let case_name = p.name.strip_prefix("__mux_case__/")?;
            if let cda_interfaces::ParameterTypeMetadata::CodedConst { coded_value } = &p.param_type
            {
                let lower = parse_mux_coded_value(coded_value)?;
                Some((lower, case_name))
            } else {
                None
            }
        })
        .collect();

    if mux_entries.is_empty() {
        return None;
    }

    // Sort by lower bound ascending.
    mux_entries.sort_by_key(|&(lb, _)| lb);

    // Floor match: largest lower_bound ≤ DID.
    let matched = mux_entries.iter().rev().find(|&&(lb, _)| lb <= did_val)?;

    Some(format!("{}/", matched.1))
}

/// Check if ANY MUX case in the response metadata **exactly** matches the DID.
///
/// Uses exact (not floor) matching because this is for cross-service sibling
/// selection where different MUX DOPs can have overlapping ranges.
#[must_use]
pub(super) fn has_mux_case_for_did_exact(meta: &[ResponseParameterInfo], did: u16) -> bool {
    let did_val = u64::from(did);
    meta.iter().any(|p| {
        if p.name.strip_prefix("__mux_case__/").is_some()
            && let cda_interfaces::ParameterTypeMetadata::CodedConst { coded_value } = &p.param_type
        {
            return parse_mux_coded_value(coded_value) == Some(did_val);
        }
        false
    })
}
