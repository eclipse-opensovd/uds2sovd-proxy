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

//! `DoIP` transport layer — ISO 13400-2.
//!
//! This crate implements the `DoIP` TCP server and per-connection handler.
//! It is intentionally decoupled from the SOVD backend: it holds a
//! `Arc<dyn DiagHandler>` (from [`uds`]) and knows nothing about HTTP,
//! MDD databases, or SOVD schemas.
//!
//! # Crate layout
//!
//! * [`config`] — [`ServerConfig`] and [`DoipConnectionConfig`].
//! * [`server`] — [`DoIpServer`]: accept connections, enforce connection limit.
//! * [`handler`] — [`ConnectionHandler`]: owns one TCP connection.
//! * [`session`] — [`Session`]: routing-activation state machine.
//! * [`message`] — `DoIP` wire-format message types and framing.
//! * `uds_dispatcher` — internal UDS SID routing (not part of the public API).
//!
//! # Usage
//!
//! ```rust,no_run
//! use std::sync::Arc;
//! use doip::{DoIpServer, config::{DoipConnectionConfig, ServerConfig}};
//! use uds::DiagHandler;
//!
//! // Implement DiagHandler for your backend, then:
//! // let handler: Arc<dyn DiagHandler> = Arc::new(MyBackend::new());
//! // let server = DoIpServer::new(ServerConfig::default(), DoipConnectionConfig { ... }, handler);
//! // server.run().await?;
//! ```

pub mod config;
pub mod handler;
pub mod message;
pub mod server;
pub mod session;
pub(crate) mod uds_dispatcher;

pub use config::{DoipConnectionConfig, ServerConfig};
pub use handler::ConnectionHandler;
pub use message::DoIpMessage;
pub use server::DoIpServer;
