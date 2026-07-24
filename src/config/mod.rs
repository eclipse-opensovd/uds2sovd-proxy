// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 The Contributors to Eclipse OpenSOVD (see CONTRIBUTORS)
//
// See the NOTICE file(s) distributed with this work for additional
// information regarding copyright ownership.
//
// This program and the accompanying materials are made available under the
// terms of the Apache License Version 2.0 which is available at
// https://www.apache.org/licenses/LICENSE-2.0

//! Configuration types and loaders.
//!
//! Provides the runtime configuration model ([`ServerConfig`]) and the abstractions
//! used to load it from different sources. Use the [`ConfigProvider`] trait to implement
//! custom configuration sources, or use the built-in providers:
//! - [`DefaultConfigProvider`]: Load built-in defaults
//! - [`TomlConfigProvider`]: Load from a TOML file

pub mod defaults;
pub mod error;
pub mod provider;
pub mod types;

pub use error::ConfigError;
pub use provider::{DefaultConfigProvider, TomlConfigProvider};
pub use types::{EcuConfig, ServerConfig, TcpConfig, UdpConfig};

/// Loads a complete [`ServerConfig`].
///
/// Implementations may obtain configuration from different sources, such as
/// TOML files or in-memory defaults.
pub trait ConfigProvider {
    /// Loads and returns a complete [`ServerConfig`].
    ///
    /// # Errors
    ///
    /// Returns [`ConfigError`] if configuration loading fails.
    fn load(&self) -> Result<ServerConfig, ConfigError>;
}
