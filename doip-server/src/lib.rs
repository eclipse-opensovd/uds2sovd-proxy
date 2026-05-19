/*
 * Copyright (c) 2026 The Contributors to Eclipse OpenSOVD (see CONTRIBUTORS)
 *
 * See the NOTICE file(s) distributed with this work for additional
 * information regarding copyright ownership.
 *
 * This program and the accompanying materials are made available under the
 * terms of the Apache License Version 2.0 which is available at
 * https://www.apache.org/licenses/LICENSE-2.0
 *
 * SPDX-License-Identifier: Apache-2.0
 */
//! `DoIP` server library (ISO 13400-2:2019 / ISO 14229-1:2020).
//!
//! Provides TCP framing ([`doip::DoipCodec`]), protocol parsing, session
//! management, and a [`uds::UdsHandler`] extension point for UDS processing.
/// Core DoIP protocol types, codec, and wire-format handlers (ISO 13400-2:2019).
pub mod doip;
/// Error types and the crate-level [`Result`] alias.
pub mod error;
/// DoIP server configuration and session management.
pub mod server;
/// UDS service layer – bridges DoIP transport to ISO 14229-1 request/response handling.
pub mod uds;
pub use error::{DoipError, Result};

// No unit tests: this file contains only module declarations and re-exports.
// All logic lives in the sub-modules, which carry their own test suites.
