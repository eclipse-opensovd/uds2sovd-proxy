// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 The Contributors to Eclipse OpenSOVD (see CONTRIBUTORS)
//
// See the NOTICE file(s) distributed with this work for additional
// information regarding copyright ownership.
//
// This program and the accompanying materials are made available under the
// terms of the Apache License Version 2.0 which is available at
// https://www.apache.org/licenses/LICENSE-2.0


//! DoIP server application.
//!
//! Standalone server binary that runs the DoIP protocol using the library.
//!
//! # Running
//!
//! ```sh
//! # With default configuration
//! cargo run --bin doip-server
//!
//! # With custom TOML configuration
//! cargo run --bin doip-server -- /path/to/config.toml
//! ```
//!
//! # Configuration
//!
//! Server loads configuration in this order (first match wins):
//! 1. CLI argument: `doip-server <path/to/config.toml>`
//! 2. Default built-in configuration from [`config::DefaultConfigProvider`]
//!
//! For configuration schema, see `docs/doip_server_usage.md`.
//!
//! # See Also
//!
//! - Main library: [uds2sovd crate](https://docs.rs/uds2sovd) for API details
//! - Example client: `cargo run --bin Example` for testing      
use std::sync::Arc;
use uds2sovd::{config, doip, error, proxy, server};

use config::{ConfigProvider, DefaultConfigProvider, ServerConfig, TomlConfigProvider};
use error::AppError;
use proxy::stub::StubProxy;
use server::Server;
use server::tcp::Tcp;
use server::udp::Udp;

#[tokio::main]
async fn main() -> Result<(), AppError> {
    tracing_subscriber::fmt::init();

    let config = match std::env::args().nth(1) {
        //TODO : Add CLI arg parsing with clap or similar for better UX and error handling.
        Some(path) => TomlConfigProvider::new(path.into()).load()?,
        None => DefaultConfigProvider::new(ServerConfig::default()).load()?,
    };

    tracing::info!("Starting DoIP server");

    // TODO: Replace StubProxy with real UDS-to-SOVD proxy implementation.
    let (tcp_config, udp_config, ecu_config) = config.into_parts();
    let tcp_dispatcher = doip::tcp_dispatcher(tcp_config.logical_address(), Arc::new(StubProxy));
    let udp_dispatcher = doip::udp_dispatcher(udp_config.logical_address(), &ecu_config);

    let tcp = Tcp::new(tcp_config, tcp_dispatcher);
    let udp = Udp::new(udp_config, udp_dispatcher);

    let server = Server::new(tcp, udp);

    // As of now shutdown is triggered by Ctrl+C, but this can be extended to support other signals or programmatic shutdown in the future.
    tokio::select! {
        result = server.start() => { result?; }
        _ = tokio::signal::ctrl_c() => {
            tracing::info!("Received shutdown signal, stopping server");
        }
    }

    Ok(())
}
