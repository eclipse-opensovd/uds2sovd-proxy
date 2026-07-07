//! Top-level application error types.
//!
//! Aggregates errors from configuration loading, transport I/O, and protocol processing.
//! Applications should handle [`AppError`] to report issues during server operation.

// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 The Contributors to Eclipse OpenSOVD (see CONTRIBUTORS)
//
// See the NOTICE file(s) distributed with this work for additional
// information regarding copyright ownership.
//
// This program and the accompanying materials are made available under the
// terms of the Apache License Version 2.0 which is available at
// https://www.apache.org/licenses/LICENSE-2.0

use crate::config::ConfigError;
use crate::doip::error::Error;

/// Top-level application error.
#[derive(Debug, thiserror::Error)]
pub enum AppError {
    /// Returned when DoIP parsing or handler execution fails.
    #[error(transparent)]
    Doip(#[from] Error),

    /// Returned when a runtime I/O operation fails.
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),

    /// Returned when configuration cannot be loaded.
    #[error("config error: {0}")]
    Config(#[from] ConfigError),
}
