// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 The Contributors to Eclipse OpenSOVD (see CONTRIBUTORS)
//
// See the NOTICE file(s) distributed with this work for additional
// information regarding copyright ownership.
//
// This program and the accompanying materials are made available under the
// terms of the Apache License Version 2.0 which is available at
// https://www.apache.org/licenses/LICENSE-2.0

//! UDP transport runtime.
//!
//! Handles incoming datagrams, dispatches them through registered handlers,
//! and sends responses back to the sender.

pub mod handler;

use std::io;
use std::sync::Arc;

use tokio::net::UdpSocket;

use super::Transport;
use crate::config::UdpConfig;
use crate::doip::UdpDispatcher;
use crate::doip::constants::UDP_RECV_BUF_SIZE;
use crate::doip::error::Error;
use handler::Handler;

/// UDP transport implementation.
///
/// Receives datagrams, dispatches them through the UDP dispatcher, and sends
/// any generated response back to the sender.
///
/// Runtime behavior per datagram:
/// - Successful dispatch: send handler response.
/// - [`Error::EIDNotMatched`] or [`Error::VinNotMatched`]: send no response.
/// - Other dispatch/parsing errors: send Generic Header NACK.
pub struct Udp {
    config: UdpConfig,
    handler: Handler,
}

impl Udp {
    /// Creates a UDP transport from the provided configuration and dispatcher.
    pub fn new(config: UdpConfig, dispatcher: UdpDispatcher) -> Self {
        Self {
            config,
            handler: Handler::new(Arc::new(dispatcher)),
        }
    }
}

impl Transport for Udp {
    /// Binds the configured UDP address and runs the receive loop.
    ///
    /// Most receive/send/dispatch errors are logged and the loop continues.
    ///
    /// # Errors
    ///
    /// Returns [`io::Error`] if the UDP socket cannot be bound.
    async fn start(&self) -> Result<(), io::Error> {
        let socket = UdpSocket::bind(self.config.address()).await?;
        tracing::info!(address = %self.config.address(), "UDP server listening");

        let mut buf = vec![0u8; UDP_RECV_BUF_SIZE];
        loop {
            match socket.recv_from(&mut buf).await {
                Ok((bytes_received, src_addr)) => {
                    match self.handler.handle(&buf[..bytes_received]) {
                        Ok(resp) => {
                            if let Err(err) = socket.send_to(&resp.to_bytes(), src_addr).await {
                                tracing::error!(error = %err, peer = %src_addr, "UDP send error");
                            }
                        }
                        // Non-matching EID/VIN request: intentionally no response.
                        Err(Error::EIDNotMatched) | Err(Error::VinNotMatched) => {
                            tracing::debug!(peer = %src_addr, "no matching entity, not responding");
                        }
                        Err(err) => {
                            tracing::warn!(error = %err, peer = %src_addr, "UDP dispatch error");
                            let nack =
                                crate::doip::message::Response::doip_header_nack(err.nack_code());
                            let _ = socket.send_to(&nack.to_bytes(), src_addr).await;
                        }
                    }
                }
                Err(err) => tracing::error!(error = %err, "UDP recv error"),
            }
        }
    }
}
