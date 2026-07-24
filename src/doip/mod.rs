// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 The Contributors to Eclipse OpenSOVD (see CONTRIBUTORS)
//
// See the NOTICE file(s) distributed with this work for additional
// information regarding copyright ownership.
//
// This program and the accompanying materials are made available under the
// terms of the Apache License Version 2.0 which is available at
// https://www.apache.org/licenses/LICENSE-2.0

//! DoIP protocol types, handlers, and dispatcher construction.

pub mod constants;
pub mod dispatch;
pub mod error;
pub mod handlers;
pub mod header;
pub mod message;
pub mod types;

pub use dispatch::{PayloadHandler, TcpDispatcher, UdpDispatcher};
pub use types::{Eid, Gid, LogicalAddress, Vin};

use std::sync::Arc;

/// Builds the TCP dispatcher with these handlers registered:
/// - [`handlers::RoutingActivationHandler`]
/// - [`handlers::AliveCheckHandler`]
/// - [`handlers::DiagnosticsHandler`]
///
/// # example
///
/// ```no_run
/// use uds2sovd_proxy_lib::doip;
/// use uds2sovd_proxy_lib::proxy::stub::StubProxy;
/// use uds2sovd_proxy_lib::doip::types::LogicalAddress;
/// use std::sync::Arc;
///
/// let stub_proxy = StubProxy;
/// let dispatcher = doip::tcp_dispatcher(
///     LogicalAddress::new(0x0001),
///     Arc::new(stub_proxy),
/// );
/// ```
pub fn tcp_dispatcher(
    logical_addr: LogicalAddress,
    proxy: Arc<dyn crate::proxy::SovdProxy>,
) -> TcpDispatcher {
    use handlers::{AliveCheckHandler, DiagnosticsHandler, RoutingActivationHandler};
    let mut dispatcher = TcpDispatcher::new();
    dispatcher.register(RoutingActivationHandler::new(logical_addr));
    dispatcher.register(AliveCheckHandler::new(logical_addr));
    dispatcher.register(DiagnosticsHandler::new(proxy));
    dispatcher
}

/// Builds the UDP dispatcher with these handlers registered:
/// - [`handlers::IdentifyVehicleHandler`]
/// - [`handlers::IdentifyVehicleByEidHandler`]
/// - [`handlers::IdentifyVehicleByVinHandler`]
/// - [`handlers::EntityStatusHandler`] with `max_connections = 10` and
///   `max_data_size = 65_535`
///
/// # example
///
/// ```no_run
/// use uds2sovd_proxy_lib::doip;
/// use uds2sovd_proxy_lib::config::EcuConfig;
/// use uds2sovd_proxy_lib::doip::types::LogicalAddress;
///
/// let ecu = EcuConfig::default();
/// let dispatcher = doip::udp_dispatcher(
///     LogicalAddress::new(0x0001),
///     &ecu,
/// );
/// ```
pub fn udp_dispatcher(
    logical_addr: LogicalAddress,
    ecu: &crate::config::EcuConfig,
) -> UdpDispatcher {
    use handlers::{
        EntityStatusHandler, IdentifyVehicleByEidHandler, IdentifyVehicleByVinHandler,
        IdentifyVehicleHandler,
    };
    let ecu = ecu.clone();
    let mut dispatcher = UdpDispatcher::new();
    dispatcher.register(IdentifyVehicleHandler::new(ecu.clone(), logical_addr));
    dispatcher.register(IdentifyVehicleByEidHandler::new(ecu.clone(), logical_addr));
    dispatcher.register(IdentifyVehicleByVinHandler::new(ecu, logical_addr));
    dispatcher.register(EntityStatusHandler::new(10, 65_535));
    dispatcher
}
