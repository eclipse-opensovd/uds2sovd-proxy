// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 The Contributors to Eclipse OpenSOVD (see CONTRIBUTORS)
//
// See the NOTICE file(s) distributed with this work for additional
// information regarding copyright ownership.
//
// This program and the accompanying materials are made available under the
// terms of the Apache License Version 2.0 which is available at
// https://www.apache.org/licenses/LICENSE-2.0

//! Errors returned by [`SovdProxy`](super::SovdProxy) implementations.

/// Errors reported by a [`SovdProxy`](super::SovdProxy).
#[derive(Debug, thiserror::Error)]
pub enum SovdProxyError {
    /// Returned when the backend response cannot be interpreted as valid UDS bytes.
    #[error("SOVD returned an invalid UDS response")]
    InvalidResponse,
}
