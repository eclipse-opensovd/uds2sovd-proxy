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

//! UDS request parameter helpers.
//!
//! Functions for extracting DID values from raw UDS bytes and matching
//! request parameters from MDD metadata against incoming DID values.

use cda_interfaces::{CompuScaleInfo, ServiceParameterMetadata};

/// Extract the 16-bit DID from UDS payload bytes at offset 1–2.
///
/// Returns `None` if the slice has fewer than 3 bytes.
pub(super) fn extract_did_from_uds(data: &[u8]) -> Option<u16> {
    let b1 = *data.get(1)?;
    let b2 = *data.get(2)?;
    Some(u16::from_be_bytes([b1, b2]))
}

/// Find the DID-bearing parameter by position and type, not by name.
///
/// In standard UDS requests parameters are stored in byte order:
/// - First `CodedConst` whose value matches the SID → SID indicator (skip)
/// - Next `CodedConst` / `PhysConst` / `Value` → DID parameter
///
/// This avoids vendor-specific name or semantic string matching.
pub(super) fn find_did_param(
    metadata: &[ServiceParameterMetadata],
    sid: u8,
) -> Option<&ServiceParameterMetadata> {
    let mut skipped_sid = false;
    for p in metadata {
        match &p.param_type {
            cda_interfaces::ParameterTypeMetadata::CodedConst { coded_value } => {
                if !skipped_sid
                    && let Some(val) = parse_u64_literal(coded_value)
                    && val == u64::from(sid)
                {
                    skipped_sid = true;
                    continue;
                }
                // Non-SID CodedConst → DID param.
                return Some(p);
            }
            cda_interfaces::ParameterTypeMetadata::PhysConst { .. }
            | cda_interfaces::ParameterTypeMetadata::Value { .. } => {
                // PhysConst / Value → DID param.
                return Some(p);
            }
            cda_interfaces::ParameterTypeMetadata::MatchingRequestParam { .. } => {}
        }
    }
    None
}

/// Check if a DID falls within any `CompuScale` range from the DOP metadata.
///
/// For TEXTTABLE DOPs each scale defines a coded (internal) DID range.
/// Returns `true` if `did` falls in `[lower_limit, upper_limit]` of any scale.
pub(super) fn did_matches_compu_scales(scales: &[CompuScaleInfo], did: u16) -> bool {
    let did_val = u64::from(did);
    scales.iter().any(|s| match (s.lower_limit, s.upper_limit) {
        (Some(lo), Some(hi)) => did_val >= lo && did_val <= hi,
        (Some(lo), None) => did_val == lo,
        _ => false,
    })
}

/// Parse numeric literals in decimal or hexadecimal (`0x`-prefixed) form.
///
/// Unprefixed strings are parsed as decimal only; the fallback hex
/// interpretation applies only when a `0x` / `0X` prefix is present.
pub(super) fn parse_u64_literal(value: &str) -> Option<u64> {
    let trimmed = value.trim();
    if let Some(hex) = trimmed
        .strip_prefix("0x")
        .or_else(|| trimmed.strip_prefix("0X"))
    {
        return u64::from_str_radix(hex, 16).ok();
    }

    // MDD files may use bare hex strings (e.g. "F103") without a prefix.
    // Try decimal first to avoid misinterpreting small pure-digit values;
    // fall back to hex only when decimal parsing fails.
    trimmed
        .parse::<u64>()
        .ok()
        .or_else(|| u64::from_str_radix(trimmed, 16).ok())
}
