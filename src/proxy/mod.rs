// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 The Contributors to Eclipse OpenSOVD (see CONTRIBUTORS)
//
// See the NOTICE file(s) distributed with this work for additional
// information regarding copyright ownership.
//
// This program and the accompanying materials are made available under the
// terms of the Apache License Version 2.0 which is available at
// https://www.apache.org/licenses/LICENSE-2.0

//! Backend proxy traits and implementations.

pub mod error;
#[cfg(test)]
pub mod mock;
pub mod stub;

pub use error::SovdProxyError;

/// Processes a raw UDS request and returns a raw UDS response.
///
/// The input and output contain UDS payload bytes only and do not include DoIP
/// framing.
///
/// This trait is synchronous; callers invoke it from the transport handler path.
pub trait SovdProxy: Send + Sync {
    /// Processes a UDS request.
    ///
    /// # Errors
    ///
    /// Returns [`SovdProxyError`] if a response cannot be produced.
    fn process(&self, uds_request: &[u8]) -> Result<Vec<u8>, SovdProxyError>;
}
