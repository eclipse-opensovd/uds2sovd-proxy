// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 The Contributors to Eclipse OpenSOVD (see CONTRIBUTORS)
//
// See the NOTICE file(s) distributed with this work for additional
// information regarding copyright ownership.
//
// This program and the accompanying materials are made available under the
// terms of the Apache License Version 2.0 which is available at
// https://www.apache.org/licenses/LICENSE-2.0

//! Transport runtimes for the DoIP server.

pub mod tcp;
pub mod udp;

use std::io;
use tcp::Tcp;
use udp::Udp;

/// Starts a transport runtime.
#[allow(async_fn_in_trait)]
pub trait Transport: Send + Sync {
    /// Starts the transport runtime.
    ///
    /// Implementations typically run an internal loop until task cancellation.
    /// Recoverable per-connection or per-datagram failures may be handled
    /// internally and logged without returning from this method.
    ///
    /// # Errors
    ///
    /// Returns [`io::Error`] when startup fails (for example, socket bind
    /// failures) or when the transport chooses to surface a fatal runtime error.
    async fn start(&self) -> Result<(), io::Error>;
}

/// Runs the TCP and UDP transports together.
pub struct Server {
    tcp: Tcp,
    udp: Udp,
}

impl Server {
    /// Creates a server from TCP and UDP transport instances.
    pub fn new(tcp: Tcp, udp: Udp) -> Self {
        Self { tcp, udp }
    }

    /// Starts both transports concurrently.
    ///
    /// # Errors
    ///
    /// Uses `tokio::try_join!` and returns the first [`io::Error`] surfaced by
    /// either transport. When one transport returns an error, the sibling future
    /// is dropped.
    pub async fn start(&self) -> Result<(), io::Error> {
        tokio::try_join!(self.tcp.start(), self.udp.start())?;
        Ok(())
    }
}
