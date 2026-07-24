// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 The Contributors to Eclipse OpenSOVD (see CONTRIBUTORS)
//
// See the NOTICE file(s) distributed with this work for additional
// information regarding copyright ownership.
//
// This program and the accompanying materials are made available under the
// terms of the Apache License Version 2.0 which is available at
// https://www.apache.org/licenses/LICENSE-2.0

//! Registry and router for DoIP payload-type handlers.
//!
//! The [`Dispatcher`] receives incoming requests, looks up the registered handler
//! for the request's payload type, and routes the request to that handler.

use std::collections::HashMap;
use std::hash::Hash;

use crate::doip::error::Error;
use crate::doip::message::{
    HasPayloadType, Response, TcpPayloadType, TcpRequest, UdpPayloadType, UdpRequest,
};

/// Handles one DoIP payload type for one transport.
pub trait PayloadHandler<PayloadType, Request>: Send + Sync {
    /// The payload type this handler is registered for.
    fn payload_type(&self) -> PayloadType;

    /// Processes a request and returns a response.
    ///
    /// # Errors
    ///
    /// Returns [`Error`] if the request is invalid or cannot be handled.
    fn handle(&self, req: Request) -> Result<Response, Error>;
}

/// Registry and router for payload-type handlers.
pub struct Dispatcher<PayloadType, Request>
where
    PayloadType: Eq + Hash,
{
    handlers: HashMap<PayloadType, Box<dyn PayloadHandler<PayloadType, Request> + Send + Sync>>,
}

impl<PayloadType, Request> Dispatcher<PayloadType, Request>
where
    PayloadType: Eq + Hash + Into<u16>,
    Request: HasPayloadType<PayloadType>,
{
    /// Creates an empty dispatcher.
    pub fn new() -> Self {
        Self {
            handlers: HashMap::new(),
        }
    }

    /// Registers a handler for its declared payload type.
    pub fn register(&mut self, handler: impl PayloadHandler<PayloadType, Request> + 'static) {
        let payload_type = handler.payload_type();
        self.handlers.insert(payload_type, Box::new(handler));
    }

    /// Routes a request to the registered handler for its payload type.
    ///
    /// # Errors
    ///
    /// Returns [`Error::UnknownPayloadType`] if no handler is registered.
    pub fn dispatch(&self, req: Request) -> Result<Response, Error> {
        let payload_type = req.payload_type();
        self.handlers
            .get(&payload_type)
            .ok_or_else(|| Error::UnknownPayloadType(payload_type.into()))?
            .handle(req)
    }
}

impl<PayloadType, Request> Default for Dispatcher<PayloadType, Request>
where
    PayloadType: Eq + Hash + Into<u16>,
    Request: HasPayloadType<PayloadType>,
{
    fn default() -> Self {
        Self::new()
    }
}

/// Dispatcher specialized for TCP payload types.
///
/// The type parameters prevent registering UDP handlers on the TCP path. For
/// example, a TCP handler cannot be registered on a UDP dispatcher:
///
/// ```compile_fail
/// use uds2sovd::doip::dispatch::UdpDispatcher;
/// use uds2sovd::doip::handlers::AliveCheckHandler;
/// use uds2sovd::doip::types::LogicalAddress;
///
/// let mut dispatcher = UdpDispatcher::new();
/// // AliveCheckHandler implements PayloadHandler<TcpPayloadType, TcpRequest>,
/// // so this will not compile on a UdpDispatcher.
/// dispatcher.register(AliveCheckHandler::new(LogicalAddress::new(0x0001)));
/// ```
pub type TcpDispatcher = Dispatcher<TcpPayloadType, TcpRequest>;

/// Dispatcher specialized for UDP payload types.
pub type UdpDispatcher = Dispatcher<UdpPayloadType, UdpRequest>;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::doip::error::Error;
    use crate::doip::message::{Response, TcpPayloadType, TcpRequest};

    struct AliveEchoHandler;

    impl PayloadHandler<TcpPayloadType, TcpRequest> for AliveEchoHandler {
        fn payload_type(&self) -> TcpPayloadType {
            TcpPayloadType::AliveCheckRequest
        }
        fn handle(&self, _req: TcpRequest) -> Result<Response, Error> {
            Ok(Response::new(
                TcpPayloadType::AliveCheckResponse as u16,
                vec![],
            ))
        }
    }

    fn make_req(pt: TcpPayloadType) -> TcpRequest {
        TcpRequest::new(pt, vec![])
    }

    #[test]
    fn dispatch_routes_to_registered_handler() {
        let mut dispatcher = TcpDispatcher::new();
        dispatcher.register(AliveEchoHandler);
        let resp = dispatcher
            .dispatch(make_req(TcpPayloadType::AliveCheckRequest))
            .unwrap();
        assert_eq!(
            resp.payload_type(),
            TcpPayloadType::AliveCheckResponse as u16
        );
    }

    #[test]
    fn dispatch_rejects_unknown_type() {
        let dispatcher = TcpDispatcher::new();
        let result = dispatcher.dispatch(make_req(TcpPayloadType::DiagnosticMessage));
        assert!(matches!(result, Err(Error::UnknownPayloadType(0x8001))));
    }
}
