// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 The Contributors to Eclipse OpenSOVD (see CONTRIBUTORS)
//
// See the NOTICE file(s) distributed with this work for additional
// information regarding copyright ownership.
//
// This program and the accompanying materials are made available under the
// terms of the Apache License Version 2.0 which is available at
// https://www.apache.org/licenses/LICENSE-2.0

//! Per-connection TCP session handling.
//!
//! Each accepted TCP connection spawns a Session that:
//! 1. Owns a ConnectionSlot (RAII session counter)
//! 2. Reads bytes from the socket
//! 3. Feeds bytes to Framer for DoIP frame extraction
//! 4. Dispatches complete frames to registered handlers
//! 5. Writes responses back to the client
//!
//! When the session ends (clean close, error, or client disconnect), the
//! ConnectionSlot is dropped, automatically decrementing the active session count.

pub(super) mod manager;
pub(super) mod slot;

pub(super) use manager::SessionManager;
pub(super) use slot::ConnectionSlot;

use std::sync::Arc;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

use crate::doip::TcpDispatcher;
use crate::doip::error::Error;
use crate::doip::message::{ConnectionId, Response, TcpRequest};
use crate::server::tcp::framer::{Frame, Framer};

/// Represents an accepted TCP connection.
///
/// Owns the `ConnectionSlot`. When `run()` returns, dropping the slot releases
/// the tracked session capacity.
pub(super) struct Session {
    slot: ConnectionSlot,
}

impl Session {
    /// Creates a session that owns the given connection slot.
    pub(super) fn new(slot: ConnectionSlot) -> Self {
        Self { slot }
    }

    /// Drive the session I/O loop until disconnection or error.
    ///
    /// # Session lifecycle
    ///
    /// 1. Read bytes from TCP stream
    /// 2. Feed to framer for frame extraction
    /// 3. Dispatch frames to handlers
    /// 4. Write responses back
    /// 5. Repeat until EOF or I/O failure
    ///
    /// # Error handling
    ///
    /// - **Framing errors**: NACK sent, session continues for next frame
    /// - **Dispatch errors**: NACK sent to client, session continues
    /// - **Write errors**: Session terminates immediately.
    /// - **Read errors**: Connection closed, error logged
    ///
    /// When this function returns, the `ConnectionSlot` is dropped,
    /// automatically decrementing the session counter.
    pub(crate) async fn run(
        self,
        mut stream: TcpStream,
        dispatcher: Arc<TcpDispatcher>,
        buf_size: usize,
    ) {
        let id = self.slot.id();
        let mut framer = Framer::new();
        let mut buf = vec![0u8; buf_size];

        loop {
            match stream.read(&mut buf).await {
                Ok(0) => {
                    tracing::info!(id = %id, "client disconnected");
                    break;
                }
                Ok(bytes_read) => {
                    for frame_result in framer.feed(&buf[..bytes_read]) {
                        if handle_frame_result(frame_result, &mut stream, id, &dispatcher)
                            .await
                            .is_err()
                        {
                            return;
                        }
                    }
                }
                Err(err) => {
                    tracing::error!(id = %id, error = %err, "read error");
                    // TODO: propagate error to caller instead of silently disconnecting
                    break;
                }
            }
        }
        // self drops here → slot drops → counter decremented
    }
}

/// Handle a single frame result from the framer.
///
/// Returns `Err(())` on fatal write errors (connection should be closed).
async fn handle_frame_result(
    result: Result<Frame, Error>,
    stream: &mut TcpStream,
    id: &ConnectionId,
    dispatcher: &TcpDispatcher,
) -> Result<(), ()> {
    match result {
        Ok(frame) => process_frame(frame, stream, id, dispatcher).await,
        Err(err) => {
            tracing::warn!(id = %id, error = %err, "framing error");
            let nack = Response::doip_header_nack(err.nack_code());
            if let Err(write_err) = stream.write_all(&nack.to_bytes()).await {
                tracing::error!(id = %id, error = %write_err, "nack write error");
                return Err(());
            }
            Ok(())
        }
    }
}

/// Dispatch a complete DoIP frame and write the response.
///
/// Returns `Err(())` if the response write fails (connection should be closed).
async fn process_frame(
    frame: Frame,
    stream: &mut TcpStream,
    id: &ConnectionId,
    dispatcher: &TcpDispatcher,
) -> Result<(), ()> {
    // TODO: Consider creating TcpRequest directly from the buffer to avoid the intermediate Frame.
    let (payload_type, payload) = frame.into_parts();
    let req = TcpRequest::new(payload_type, payload);
    match dispatcher.dispatch(req) {
        Ok(resp) => {
            if let Err(err) = stream.write_all(&resp.to_bytes()).await {
                tracing::error!(id = %id, error = %err, "write error");
                return Err(());
            }
        }
        Err(err) => {
            tracing::warn!(id = %id, error = %err, "dispatch error");
            let nack = Response::doip_header_nack(err.nack_code());
            if let Err(write_err) = stream.write_all(&nack.to_bytes()).await {
                tracing::error!(id = %id, error = %write_err, "nack write error");
                return Err(());
            }
        }
    }
    Ok(())
}
