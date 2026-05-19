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

//! UDS Module
//!
//! Provides the interface between `DoIP` transport and UDS processing.

/// UDS handler trait and request/response types bridging DoIP and ISO 14229-1.
pub mod handler;

pub use handler::{UdsHandler, UdsRequest, UdsResponse, service_id};

// No unit tests: this file contains only module declarations and re-exports.
// handler.rs carries its own test suite.
