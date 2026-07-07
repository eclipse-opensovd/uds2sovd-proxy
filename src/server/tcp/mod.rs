// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 The Contributors to Eclipse OpenSOVD (see CONTRIBUTORS)
//
// See the NOTICE file(s) distributed with this work for additional
// information regarding copyright ownership.
//
// This program and the accompanying materials are made available under the
// terms of the Apache License Version 2.0 which is available at
// https://www.apache.org/licenses/LICENSE-2.0

//! TCP transport runtime.

mod framer;
mod session;

use std::io;
use std::sync::Arc;

use tokio::io::AsyncWriteExt;
use tokio::net::TcpListener;

use super::Transport;
use crate::config::TcpConfig;
use crate::doip::TcpDispatcher;
use crate::doip::message::{DoipNackCode, Response};
use session::{Session, SessionManager};

/// TCP transport implementation.
///
/// Accepts connections, enforces the configured session limit, and dispatches
/// framed DoIP messages to the TCP dispatcher.
///
/// When the session limit is reached, the transport sends a Generic Header
/// NACK with [`DoipNackCode::OutOfMemory`] and then closes the connection.
pub struct Tcp {
    config: TcpConfig,
    manager: SessionManager,
    dispatcher: Arc<TcpDispatcher>,
}

impl Tcp {
    /// Creates a TCP transport from the provided configuration and dispatcher.
    pub fn new(config: TcpConfig, dispatcher: TcpDispatcher) -> Self {
        let manager = SessionManager::new(config.max_connections());
        Self {
            config,
            manager,
            dispatcher: Arc::new(dispatcher),
        }
    }
}

impl Transport for Tcp {
    /// Binds the configured TCP address and runs the accept loop.
    ///
    /// Most accept/session errors are logged and the loop continues.
    ///
    /// # Errors
    ///
    /// Returns [`io::Error`] if the listener cannot be bound.
    async fn start(&self) -> Result<(), io::Error> {
        let listener = TcpListener::bind(self.config.address()).await?;
        tracing::info!(address = %self.config.address(), "TCP server listening");

        loop {
            match listener.accept().await {
                Ok((mut stream, peer_addr)) => match self.manager.try_acquire() {
                    Some(slot) => {
                        tracing::info!(peer = %peer_addr, id = %slot.id(), "new TCP connection");
                        let session = Session::new(slot);
                        let dispatcher = Arc::clone(&self.dispatcher);
                        let buf_size = self.config.read_buffer_size();
                        tokio::spawn(async move {
                            session.run(stream, dispatcher, buf_size).await;
                        });
                    }
                    // Server is at capacity: send OutOfMemory NACK, then close.
                    None => {
                        tracing::warn!(peer = %peer_addr, "connection rejected: max sessions reached");
                        let nack = Response::doip_header_nack(DoipNackCode::OutOfMemory);
                        let _ = AsyncWriteExt::write_all(&mut stream, &nack.to_bytes()).await;
                        drop(stream);
                    }
                },
                Err(err) => tracing::error!(error = %err, "TCP accept error"),
            }
        }
    }
}
