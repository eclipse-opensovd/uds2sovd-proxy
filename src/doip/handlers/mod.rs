// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 The Contributors to Eclipse OpenSOVD (see CONTRIBUTORS)
//
// See the NOTICE file(s) distributed with this work for additional
// information regarding copyright ownership.
//
// This program and the accompanying materials are made available under the
// terms of the Apache License Version 2.0 which is available at
// https://www.apache.org/licenses/LICENSE-2.0

//! Public DoIP payload handlers.
//!
//! Handlers process incoming DoIP requests and produce responses. Each handler
//! implements the [`crate::doip::PayloadHandler`] trait for a specific payload type.
//!
//! # Built-in Handlers
//!
//! - [`AliveCheckHandler`]: Responds to alive check requests to verify connectivity
//! - [`RoutingActivationHandler`]: Manages client registration and session lifecycle
//! - [`DiagnosticsHandler`]: Routes UDS diagnostic requests to the backend proxy
//! - [`IdentifyVehicleHandler`]: General vehicle identification for UDP
//! - [`IdentifyVehicleByVinHandler`]: VIN-based vehicle identification
//! - [`IdentifyVehicleByEidHandler`]: EID-based vehicle identification
//! - [`EntityStatusHandler`]: Reports server status and session limits
//!
//! # Extension
//!
//! Implement the [`crate::doip::PayloadHandler`] trait to add custom message handling:
//!
//! ```ignore
//! use doipserver_lib::doip::{PayloadHandler, Response};
//! use doipserver_lib::doip::types::LogicalAddress;
//!
//! struct MyHandler;
//!
//! impl PayloadHandler<MyPayloadType, MyRequestType> for MyHandler {
//!     fn payload_type(&self) -> MyPayloadType { /* ... */ }
//!     fn handle(&self, req: MyRequestType) -> Result<Response, Error> { /* ... */ }
//! }
//! ```

pub mod alive_check;
pub mod diagnostics;
pub mod entity_status;
pub mod routing_activation;
pub mod vehicle_identification;

pub use alive_check::AliveCheckHandler;
pub use diagnostics::DiagnosticsHandler;
pub use entity_status::EntityStatusHandler;
pub use routing_activation::RoutingActivationHandler;
pub use vehicle_identification::{
    IdentifyVehicleByEidHandler, IdentifyVehicleByVinHandler, IdentifyVehicleHandler,
};
