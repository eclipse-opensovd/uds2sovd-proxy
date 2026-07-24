// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 The Contributors to Eclipse OpenSOVD (see CONTRIBUTORS)
//
// See the NOTICE file(s) distributed with this work for additional
// information regarding copyright ownership.
//
// This program and the accompanying materials are made available under the
// terms of the Apache License Version 2.0 which is available at
// https://www.apache.org/licenses/LICENSE-2.0

#![doc = include_str!("../docs/detailed_design.md")]

//! # UDS-to-SOVD Library
//!
//! Implements ISO 13400-2 Diagnostics over Internet Protocol (DoIP) as a bridge
//! between UDS (Unified Diagnostic Services) and SOVD backends.
//!
//! This library provides the core protocol implementation and is the foundation for the application:
//!
//! - `uds2sovd-proxy-lib`: the library crate with the DoIP protocol and backend logic
//! - `uds2sovd-proxy`: the standalone UDS-to-SOVD Proxy application
//! - `doip-tester`: the manual tester tool used to exercise the application
//!
//! For application-level workflows, use the server application and tester tool.
//!
//! # Quick Start
//!
//! ```no_run
//! use uds2sovd_proxy_lib::{config, doip, proxy};
//! use uds2sovd_proxy_lib::config::ConfigProvider;
//! use std::sync::Arc;
//!
//! let cfg = config::DefaultConfigProvider::new(config::ServerConfig::default()).load()?;
//! let (tcp_cfg, udp_cfg, ecu_cfg) = cfg.into_parts();
//! let tcp_dispatcher = doip::tcp_dispatcher(tcp_cfg.logical_address(), Arc::new(proxy::stub::StubProxy));
//! let udp_dispatcher = doip::udp_dispatcher(udp_cfg.logical_address(), &ecu_cfg);
//! # Ok::<(), Box<dyn std::error::Error>>(())
//! ```
//!
//! # Core Modules
//!
//! - [`config`]: Configuration loading from defaults or TOML files
//! - [`doip`]: Protocol types, dispatchers, and message handling
//! - [`server`]: TCP and UDP transport runtimes
//! - [`proxy`]: Backend diagnostic interface and implementations
//! - [`error`]: Application-level error aggregation
//!
//! # Implementing a Backend
//!
//! Implement the [`proxy::SovdProxy`] trait to connect your diagnostic system:
//!
//! ```ignore
//! use uds2sovd_proxy_lib::proxy::SovdProxy;
//!
//! pub struct MyBackend;
//!
//! impl SovdProxy for MyBackend {
//!     fn process(&self, uds_request: &[u8]) -> Result<Vec<u8>, _> {
//!         // Forward UDS request to your diagnostic backend
//!         // Return the response bytes
//!         Ok(Vec::new())
//!     }
//! }
//! ```
//!
//! # Learn More
//!
//! - **API Documentation**: Explore modules and types above
//! - **Architecture**: See embedded design documentation below
//! - **Running the Server**: See the `uds2sovd-proxy` crate docs for the standalone server
//! - **Testing**: See the `doip-tester` crate docs for the tester tool

pub mod config;
pub mod doip;
pub mod error;
pub mod proxy;
pub mod server;
