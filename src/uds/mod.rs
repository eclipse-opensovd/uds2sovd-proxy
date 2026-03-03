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

// #[cfg(any(test, feature = "test-handlers"))]
// pub mod dummy_handler;
pub mod handler;
// #[cfg(any(test, feature = "test-handlers"))]
// pub mod stub_handler;

pub use handler::{service_id, UdsHandler, UdsRequest, UdsResponse};
