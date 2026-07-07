// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 The Contributors to Eclipse OpenSOVD (see CONTRIBUTORS)
//
// See the NOTICE file(s) distributed with this work for additional
// information regarding copyright ownership.
//
// This program and the accompanying materials are made available under the
// terms of the Apache License Version 2.0 which is available at
// https://www.apache.org/licenses/LICENSE-2.0

//! Errors returned while loading configuration.

/// Errors produced while loading server configuration.
#[derive(Debug, thiserror::Error)]
pub enum ConfigError {
    /// Returned when the configuration source cannot be read.
    #[error("Failed to read config file: {0}")]
    FileRead(#[from] std::io::Error),

    /// Returned when TOML content cannot be deserialized into a server configuration.
    #[error("Failed to parse TOML config: {0}")]
    ParseError(#[from] toml::de::Error),
}
