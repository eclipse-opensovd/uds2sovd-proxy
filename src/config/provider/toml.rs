// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 The Contributors to Eclipse OpenSOVD (see CONTRIBUTORS)
//
// See the NOTICE file(s) distributed with this work for additional
// information regarding copyright ownership.
//
// This program and the accompanying materials are made available under the
// terms of the Apache License Version 2.0 which is available at
// https://www.apache.org/licenses/LICENSE-2.0

//! TOML-backed configuration provider.
//!
//! This provider loads server configuration from a TOML file
//! and deserializes it into a [`ServerConfig`].

use std::path::PathBuf;

use crate::config::types::ServerConfig;
use crate::config::{ConfigError, ConfigProvider};

/// [`ConfigProvider`] that reads configuration from a TOML file.
pub struct TomlConfigProvider {
    /// Path to the TOML configuration file.
    path: PathBuf,
}

impl TomlConfigProvider {
    /// Creates a provider for the specified TOML file path.
    pub fn new(path: PathBuf) -> Self {
        Self { path }
    }
}

impl ConfigProvider for TomlConfigProvider {
    /// Loads configuration from the configured TOML file.
    ///
    /// # Errors
    ///
    /// Returns [`ConfigError::FileRead`] when the file cannot be read, or
    /// [`ConfigError::ParseError`] when TOML deserialization into
    /// [`ServerConfig`] fails.
    fn load(&self) -> Result<ServerConfig, ConfigError> {
        let content = std::fs::read_to_string(&self.path)?;
        let config = toml::from_str(&content)?;
        Ok(config)
    }
}
