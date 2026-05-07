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

//! `DoIP` TCP server: accept loop, connection-limit semaphore, and task spawning.

use std::{net::SocketAddr, sync::Arc};

use tokio::{net::TcpListener, sync::Semaphore};
use tracing::{error, info, warn};
use uds::{DiagHandler, Result};

use crate::{
    config::{DoipConnectionConfig, ServerConfig},
    handler::ConnectionHandler,
};

/// `DoIP` TCP server that accepts connections and spawns per-connection handlers.
///
/// Each incoming TCP connection is handled by a [`ConnectionHandler`] that
/// reads `DoIP` frames, dispatches UDS requests to the injected
/// [`SovdDiagHandler`], and returns the encoded response.
///
/// The connection limit is enforced via a [`Semaphore`]: `try_acquire` is
/// atomic so there is no TOCTOU window between checking and incrementing.
///
/// - TODO(doip): Add UDP announcement/discovery (ISO 13400-2 #7.3) so
///   diagnostic tools can discover the proxy via Vehicle Identification.
/// - TODO(doip): Add TLS support for secure `DoIP` connections.
/// - TODO(doip): Add per-connection inactivity timeout (`T_TCP_General_Inactivity`).
pub struct DoIpServer {
    /// `DoIP` server binding configuration: port, address, max connections.
    server_config: ServerConfig,
    /// Per-connection addressing: ECU logical address and tester source address.
    conn_config: DoipConnectionConfig,
    /// Backend diagnostic handler injected at construction time.
    diag_handler: Arc<dyn DiagHandler>,
    /// Semaphore limiting the number of concurrent TCP connections.
    ///
    /// Each accepted connection acquires one permit; the permit is released
    /// when the spawned task ends, regardless of how it exits.
    connection_limit: Arc<Semaphore>,
}

impl DoIpServer {
    /// Create a new `DoIP` server with a diagnostic handler.
    ///
    /// The handler is constructed and wired in `uds2sovd`, keeping the
    /// `DoIP` layer decoupled from the concrete SOVD backend.
    #[must_use]
    pub fn new(
        server_config: ServerConfig,
        conn_config: DoipConnectionConfig,
        diag_handler: Arc<dyn DiagHandler>,
    ) -> Self {
        let permits = server_config.max_connections;
        Self {
            server_config,
            conn_config,
            diag_handler,
            connection_limit: Arc::new(Semaphore::new(permits)),
        }
    }

    /// Start the `DoIP` TCP server and accept connections in a loop.
    ///
    /// # Errors
    /// Returns an error if the server cannot bind or accept connections.
    pub async fn run(&self) -> Result<()> {
        let addr = SocketAddr::new(self.server_config.bind_address, self.server_config.doip_port);

        info!("Starting DoIP server on {}", addr);

        let listener = TcpListener::bind(addr).await?;
        info!("════════════════════════════════════════════════════════════════════════");
        info!("DoIP server listening on {}", addr);
        info!("UDS2SOVD Proxy ready to accept connections");
        info!("════════════════════════════════════════════════════════════════════════");

        let limit = self.server_config.max_connections;

        loop {
            match listener.accept().await {
                Ok((stream, peer_addr)) => {
                    // try_acquire is atomic: either we hold a permit or we don't —
                    // no window exists where two tasks can both see "room available"
                    // when only one slot remains.
                    let Ok(permit) =
                        Arc::clone(&self.connection_limit).try_acquire_owned()
                    else {
                        let active = limit.saturating_sub(
                            self.connection_limit.available_permits(),
                        );
                        warn!(
                            "Rejecting connection from {} — connection limit {}/{} reached",
                            peer_addr, active, limit,
                        );
                        drop(stream);
                        continue;
                    };

                    let active =
                        limit.saturating_sub(self.connection_limit.available_permits());
                    info!(
                        "Accepted connection from {} (active connections: {}/{})",
                        peer_addr, active, limit,
                    );

                    let conn_config = self.conn_config;
                    let diag_handler = Arc::clone(&self.diag_handler);

                    tokio::spawn(async move {
                        // permit is moved into the task; dropped when the task ends,
                        // which releases the slot back to the semaphore.
                        let _permit = permit;
                        let handler = ConnectionHandler::new(conn_config, diag_handler, stream);
                        if let Err(e) = handler.handle().await {
                            error!("Connection handler error: {}", e);
                        }
                    });
                }
                Err(e) => {
                    error!("Failed to accept connection: {}", e);
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use tokio::sync::Semaphore;

    /// Verify that `try_acquire_owned` is atomic: acquiring all permits leaves
    /// none for a concurrent caller, with no TOCTOU window.
    #[test]
    fn semaphore_try_acquire_is_atomic() {
        let sem = Semaphore::new(2);

        let p1 = sem.try_acquire().expect("first permit");
        let p2 = sem.try_acquire().expect("second permit");
        assert!(
            sem.try_acquire().is_err(),
            "no permit should be available when limit is exhausted"
        );

        drop(p1);
        assert_eq!(
            sem.available_permits(),
            1,
            "dropping one permit should restore one slot"
        );

        drop(p2);
        assert_eq!(
            sem.available_permits(),
            2,
            "dropping both permits should restore all slots"
        );
    }

    /// Verify that N simultaneous `try_acquire` calls on a semaphore with 1
    /// permit grant exactly 1 success — no over-admission possible.
    #[test]
    fn semaphore_admits_at_most_max_connections() {
        let limit = 1usize;
        let sem = std::sync::Arc::new(Semaphore::new(limit));

        // Hold all acquired permits in a Vec so they are not dropped between
        // iterations — this simulates concurrent tasks all trying at once.
        let mut held = Vec::new();
        let mut admitted = 0usize;
        for _ in 0..5 {
            if let Ok(p) = sem.try_acquire() {
                admitted += 1;
                held.push(p);
            }
        }

        assert_eq!(
            admitted, limit,
            "exactly {limit} connection(s) should be admitted"
        );
        drop(held);
        assert_eq!(sem.available_permits(), limit, "all permits released after drop");
    }

    /// Verify that `available_permits` accurately reflects the current slot count.
    #[test]
    fn semaphore_available_permits_tracks_active_connections() {
        let max = 4usize;
        let sem = Semaphore::new(max);

        assert_eq!(sem.available_permits(), max);

        let p1 = sem.try_acquire().unwrap();
        assert_eq!(sem.available_permits(), 3);

        let p2 = sem.try_acquire().unwrap();
        assert_eq!(sem.available_permits(), 2);

        drop(p1);
        assert_eq!(sem.available_permits(), 3);

        drop(p2);
        assert_eq!(sem.available_permits(), max);
    }
}

