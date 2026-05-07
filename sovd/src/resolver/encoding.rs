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

//! UDS byte encoding helpers.
//!
//! Pure functions for converting JSON values into raw UDS response bytes.
//! These have no dependency on CDA types.

/// Encode an unsigned integer as big-endian bytes (minimum width).
///
/// Zero encodes as `[0x00]`.
pub(super) fn encode_unsigned_be(num: u64) -> Vec<u8> {
    if num == 0 {
        return vec![0x00];
    }
    num.to_be_bytes()
        .iter()
        .copied()
        .skip_while(|&b| b == 0)
        .collect()
}

/// Encode a JSON value into `buf[pos..pos+size]` using big-endian representation.
///
/// Handles numbers, strings, byte arrays, and booleans.  Fills the entire
/// `size` field, zero-padding on the left for numbers shorter than `size`.
pub(super) fn encode_value_at(
    buf: &mut [u8],
    pos: usize,
    size: usize,
    value: Option<&serde_json::Value>,
) {
    let (Some(value), Some(end)) = (
        value,
        pos.checked_add(size)
            .filter(|&e| size > 0 && e <= buf.len()),
    ) else {
        return;
    };

    match value {
        serde_json::Value::Number(n) => {
            let raw = n
                .as_u64()
                .unwrap_or_else(|| n.as_i64().unwrap_or(0).cast_unsigned());
            let be = raw.to_be_bytes();
            // Right-align in the field.
            let u64_size = std::mem::size_of::<u64>();
            let start = u64_size.saturating_sub(size);
            let copy = size.min(u64_size);
            // end = pos + size; dst_start = end - copy = pos + (size - copy).
            // copy <= size so no underflow.
            let dst_start = end.saturating_sub(copy);
            if let (Some(dst), Some(src)) = (
                buf.get_mut(dst_start..end),
                be.get(start..start.saturating_add(copy)),
            ) {
                dst.copy_from_slice(src);
            }
        }
        serde_json::Value::String(s) => {
            let bytes = s.as_bytes();
            let copy = bytes.len().min(size);
            if let (Some(dst), Some(src)) = (
                buf.get_mut(pos..pos.saturating_add(copy)),
                bytes.get(..copy),
            ) {
                dst.copy_from_slice(src);
            }
        }
        serde_json::Value::Array(arr) => {
            for (i, item) in arr.iter().enumerate() {
                if i >= size {
                    break;
                }
                if let Some(byte) = item.as_u64()
                    && let Some(slot) = buf.get_mut(pos.saturating_add(i))
                {
                    #[allow(clippy::cast_possible_truncation)]
                    {
                        *slot = byte as u8;
                    }
                }
            }
        }
        serde_json::Value::Bool(b) => {
            if let Some(slot) = buf.get_mut(pos) {
                *slot = u8::from(*b);
            }
        }
        _ => {}
    }
}

/// Serialize a JSON value into raw bytes for UDS encoding.
///
/// Returns an empty `Vec` when the value is `None` or cannot be serialized.
pub(super) fn value_to_bytes(value: Option<&serde_json::Value>) -> Vec<u8> {
    let Some(value) = value else {
        return Vec::new();
    };
    match value {
        serde_json::Value::Number(n) => {
            let raw = n
                .as_u64()
                .unwrap_or_else(|| n.as_i64().unwrap_or(0).cast_unsigned());
            encode_unsigned_be(raw)
        }
        serde_json::Value::String(s) => s.as_bytes().to_vec(),
        serde_json::Value::Array(arr) => arr
            .iter()
            .filter_map(|item| {
                let byte = item.as_u64()?;
                #[allow(clippy::cast_possible_truncation)]
                Some(byte as u8)
            })
            .collect(),
        serde_json::Value::Bool(b) => vec![u8::from(*b)],
        _ => Vec::new(),
    }
}
