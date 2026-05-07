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

//! `DoIP` connection handler.
//!
//! [`ConnectionHandler`] owns exactly one TCP connection. Its responsibilities
//! are limited to the `DoIP` transport layer:
//!
//! - Reading bytes from the socket into a [`FrameBuffer`].
//! - Framing: extracting complete [`DoIpMessage`] frames, re-syncing on
//!   corrupt headers one byte at a time.
//! - Session: enforcing routing activation before accepting diagnostic traffic.
//! - Dispatch: routing each frame to the first matching [`PayloadHandler`].
//! - Writing serialised `DoIP` response frames back to the socket.
//!
//! UDS semantics (SID dispatch, DID extraction, NRC construction) are
//! delegated entirely to [`UdsDispatcher`] via the registered handlers.
//!
//! # Adding a new `DoIP` payload type
//!
//! Create a struct that implements [`PayloadHandler`] and add it to the
//! `handlers` vec in [`ConnectionHandler::new`]. No existing code changes.
//! See [`payload_handler`] for the full extension guide.

mod diagnostic;
mod frame_buffer;
mod payload_handler;
mod routing;

use std::{net::SocketAddr, sync::Arc};

use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpStream,
};
use tracing::{debug, error, info, warn};
use uds::{DiagHandler, Result};

use crate::{
    config::DoipConnectionConfig,
    message::DoIpMessage,
    session::Session,
    uds_dispatcher::UdsDispatcher,
};
use diagnostic::DiagnosticMessageHandler;
use frame_buffer::{FrameBuffer, FrameResult, MAX_FRAMES_PER_READ, READ_BUFFER_SIZE};
use payload_handler::{HandlerContext, PayloadHandler};
use routing::RoutingActivationHandler;

/// Handles a single `DoIP` TCP connection.
///
/// Owns the socket, the frame accumulation buffer, the session state, and an
/// ordered list of [`PayloadHandler`] implementations.
///
/// Construct with [`ConnectionHandler::new`], then drive the connection with
/// [`handle`](ConnectionHandler::handle).
pub struct ConnectionHandler {
    /// Immutable connection config and UDS dispatcher — shared with handlers.
    ctx: HandlerContext,
    /// Active TCP stream for this connection.
    stream: TcpStream,
    /// `DoIP` routing-activation session state.
    session: Session,
    /// Accumulation buffer for partial `DoIP` frames.
    frame_buf: FrameBuffer,
    /// Ordered list of payload handlers. First match wins per frame.
    handlers: Vec<Box<dyn PayloadHandler>>,
}

impl ConnectionHandler {
    /// Create a new connection handler with the default `DoIP` payload handler set.
    ///
    /// The default set handles:
    /// - `RoutingActivationRequest` (0x0005) — activates the session and replies
    ///   with a `RoutingActivationResponse`.
    /// - `DiagnosticMessage` (0x8001) — validates guards, dispatches UDS bytes,
    ///   and returns the UDS response wrapped in a `DiagnosticMessage`.
    pub fn new(
        conn_config: DoipConnectionConfig,
        diag_handler: Arc<dyn DiagHandler>,
        stream: TcpStream,
    ) -> Self {
        Self {
            ctx: HandlerContext {
                conn_config,
                dispatcher: UdsDispatcher::new(diag_handler),
            },
            stream,
            session: Session::new(),
            frame_buf: FrameBuffer::new(READ_BUFFER_SIZE),
            handlers: vec![
                Box::new(RoutingActivationHandler),
                Box::new(DiagnosticMessageHandler),
            ],
        }
    }

    /// Run the connection loop until the client disconnects or an unrecoverable
    /// I/O error occurs.
    ///
    /// Consumes `self`. All sub-components are released on return.
    ///
    /// # Errors
    ///
    /// Returns an error if an unrecoverable I/O error occurs on the TCP stream
    /// or if a [`PayloadHandler`] propagates an error.
    pub async fn handle(self) -> Result<()> {
        let Self {
            ctx,
            mut stream,
            mut session,
            mut frame_buf,
            handlers,
        } = self;

        let peer_addr = stream.peer_addr()?;
        info!("New connection from {}", peer_addr);

        let mut read_buf = vec![0u8; READ_BUFFER_SIZE];

        loop {
            match stream.read(&mut read_buf).await {
                Ok(0) => {
                    info!("Client {} disconnected", peer_addr);
                    break;
                }
                Ok(n) => {
                    debug!("Received {} bytes from {}", n, peer_addr);
                    frame_buf.push(read_buf.get(..n).unwrap_or_default());

                    Self::drain_frames(
                        &mut frame_buf,
                        &mut session,
                        &ctx,
                        &mut stream,
                        &handlers,
                        peer_addr,
                    )
                    .await?;

                    if frame_buf.is_overflow() {
                        warn!("Buffer too large ({} bytes), clearing", frame_buf.len());
                        frame_buf.clear();
                    }
                }
                Err(e) => {
                    error!("Error reading from client {}: {}", peer_addr, e);
                    break;
                }
            }
        }

        Ok(())
    }

    /// Extract and dispatch all complete frames from the buffer.
    ///
    /// Stops after [`MAX_FRAMES_PER_READ`] frames or when no more complete
    /// frames are available. Re-syncs one byte at a time on invalid headers.
    async fn drain_frames(
        frame_buf: &mut FrameBuffer,
        session: &mut Session,
        ctx: &HandlerContext,
        stream: &mut TcpStream,
        handlers: &[Box<dyn PayloadHandler>],
        peer_addr: SocketAddr,
    ) -> Result<()> {
        let mut frames_parsed = 0usize;

        while frames_parsed < MAX_FRAMES_PER_READ {
            match frame_buf.try_next() {
                FrameResult::Complete(msg, size) => {
                    let responses =
                        match Self::dispatch_frame(&msg, session, ctx, handlers).await {
                            Ok(r) => r,
                            Err(e) => {
                                error!("Error processing message from {}: {}", peer_addr, e);
                                return Err(e);
                            }
                        };
                    for resp in responses {
                        Self::send_to_stream(stream, &resp).await?;
                    }
                    frame_buf.consume(size);
                    frames_parsed = frames_parsed.saturating_add(1);
                }
                FrameResult::InvalidHeader => {
                    warn!(
                        "Invalid `DoIP` header from {}, discarding one byte to re-sync",
                        peer_addr,
                    );
                    frame_buf.skip_byte();
                }
                FrameResult::Incomplete => break,
            }
        }

        if frames_parsed == MAX_FRAMES_PER_READ {
            warn!(
                "Reached frame processing cap ({}) for {}, remaining buffered={} bytes",
                MAX_FRAMES_PER_READ,
                peer_addr,
                frame_buf.len(),
            );
        }

        Ok(())
    }

    /// Route one `DoIP` frame to the first matching [`PayloadHandler`].
    ///
    /// Returns an empty `Vec` for unrecognised or unsupported payload types;
    /// no response frame is sent in that case.
    async fn dispatch_frame(
        msg: &DoIpMessage,
        session: &mut Session,
        ctx: &HandlerContext,
        handlers: &[Box<dyn PayloadHandler>],
    ) -> Result<Vec<DoIpMessage>> {
        let payload_type = msg.payload_type_enum();
        debug!(
            "Received `DoIP` message: {:?}, payload_len={}",
            payload_type,
            msg.payload.len(),
        );

        if let Some(pt) = payload_type {
            for handler in handlers {
                if handler.handles(pt) {
                    return handler.handle(msg, session, ctx).await;
                }
            }
        }

        debug!("Unsupported payload type: {:?}", payload_type);
        Ok(vec![])
    }

    /// Serialise a `DoIP` message and write it to the TCP stream.
    ///
    /// # Errors
    ///
    /// Returns an error if the write or flush fails.
    async fn send_to_stream(stream: &mut TcpStream, msg: &DoIpMessage) -> Result<()> {
        stream.write_all(&msg.to_bytes()).await?;
        stream.flush().await?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use tokio::{
        io::{AsyncReadExt, AsyncWriteExt},
        net::TcpListener,
    };
    use uds::{DiagHandler, ReadDid, Result, WriteDid, error::Nrc, uds_service_ids as service_ids};

    use crate::{
        config::DoipConnectionConfig,
        message::{DOIP_HEADER_SIZE, DiagnosticMessage, DoIpMessage, PayloadType},
    };

    use super::*;

    // ── MockDiagHandler ───────────────────────────────────────────────────────

    struct MockDiagHandler {
        read_response: Vec<u8>,
        write_response: Vec<u8>,
    }

    impl MockDiagHandler {
        fn with_responses(read_response: Vec<u8>, write_response: Vec<u8>) -> Arc<dyn DiagHandler> {
            Arc::new(Self {
                read_response,
                write_response,
            })
        }

        fn ok_read(did: u16) -> Arc<dyn DiagHandler> {
            let response = vec![
                service_ids::READ_DATA_BY_IDENTIFIER | service_ids::POSITIVE_RESPONSE_BITMASK,
                (did >> 8) as u8,
                (did & 0xFF) as u8,
            ];
            Self::with_responses(response.clone(), response)
        }
    }

    #[async_trait::async_trait]
    impl DiagHandler for MockDiagHandler {
        async fn read_did(&self, _req: &ReadDid) -> Result<Vec<u8>> {
            Ok(self.read_response.clone())
        }

        async fn write_did(&self, _req: &WriteDid) -> Result<Vec<u8>> {
            Ok(self.write_response.clone())
        }
    }

    // ── Helpers ───────────────────────────────────────────────────────────────

    fn test_conn_config() -> DoipConnectionConfig {
        DoipConnectionConfig {
            ecu_logical_address: 0x0001,
            source_address: 0x0E80,
        }
    }

    fn ecu_addr() -> u16 {
        0x0001
    }

    fn make_doip_frame(payload_type: PayloadType, payload: &[u8]) -> Vec<u8> {
        DoIpMessage::new(payload_type, payload.to_vec()).to_bytes()
    }

    fn routing_activation_payload(source_address: u16) -> Vec<u8> {
        let mut p = Vec::new();
        p.extend_from_slice(&source_address.to_be_bytes());
        p.push(0x00);
        p.extend_from_slice(&[0x00, 0x00, 0x00, 0x00]);
        p
    }

    fn diag_msg_payload(source_address: u16, target_address: u16, uds: &[u8]) -> Vec<u8> {
        DiagnosticMessage {
            source_address,
            target_address,
            user_data: uds.to_vec(),
        }
        .into()
    }

    async fn spawn_handler(
        conn_config: DoipConnectionConfig,
        diag_handler: Arc<dyn DiagHandler>,
    ) -> tokio::net::TcpStream {
        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind loopback");
        let addr = listener.local_addr().expect("local addr");

        tokio::spawn(async move {
            let (stream, _) = listener.accept().await.expect("accept");
            let handler = ConnectionHandler::new(conn_config, diag_handler, stream);
            let _ = handler.handle().await;
        });

        tokio::net::TcpStream::connect(addr)
            .await
            .expect("connect loopback")
    }

    async fn read_exact_bytes(stream: &mut tokio::net::TcpStream, n: usize) -> Vec<u8> {
        let mut buf = vec![0u8; n];
        stream.read_exact(&mut buf).await.expect("read_exact");
        buf
    }

    async fn read_doip_frame(stream: &mut tokio::net::TcpStream) -> DoIpMessage {
        let header = read_exact_bytes(stream, DOIP_HEADER_SIZE).await;
        let pl_len = u32::from_be_bytes(
            header
                .get(4..8)
                .expect("header slice")
                .try_into()
                .expect("4 bytes"),
        ) as usize;
        let payload = if pl_len > 0 {
            read_exact_bytes(stream, pl_len).await
        } else {
            vec![]
        };
        let mut raw = header;
        raw.extend_from_slice(&payload);
        DoIpMessage::try_from(raw.as_slice()).expect("valid DoIP frame")
    }

    // ── Integration tests ─────────────────────────────────────────────────────

    #[tokio::test]
    async fn routing_activation_returns_success_response() {
        let mut client = spawn_handler(test_conn_config(), MockDiagHandler::ok_read(0xF190)).await;

        client
            .write_all(&make_doip_frame(
                PayloadType::RoutingActivationRequest,
                &routing_activation_payload(0x0E00),
            ))
            .await
            .expect("write activation");

        let response = read_doip_frame(&mut client).await;
        assert_eq!(
            response.payload_type_enum(),
            Some(PayloadType::RoutingActivationResponse),
        );
        assert_eq!(
            response.payload.get(4).copied(),
            Some(ROUTING_ACTIVATION_SUCCESS),
        );
        // ISO 13400-2 Table 19: response must be at least 9 bytes
        // (source_addr + entity_addr + response_code + 4 reserved bytes).
        assert_eq!(response.payload.len(), 9);
        assert_eq!(response.payload.get(5..9), Some([0x00u8; 4].as_slice()));
    }

    #[tokio::test]
    async fn diagnostic_message_before_activation_is_silently_ignored() {
        let ecu_addr = ecu_addr();
        let mut client = spawn_handler(test_conn_config(), MockDiagHandler::ok_read(0xF190)).await;

        let uds = [service_ids::READ_DATA_BY_IDENTIFIER, 0xF1, 0x90];
        client
            .write_all(&make_doip_frame(
                PayloadType::DiagnosticMessage,
                &diag_msg_payload(0x0E00, ecu_addr, &uds),
            ))
            .await
            .expect("write diag msg");

        client.shutdown().await.expect("shutdown");
        let mut buf = [0u8; 64];
        let n = client.read(&mut buf).await.expect("read");
        assert_eq!(n, 0, "no response expected before routing activation");
    }

    #[tokio::test]
    async fn diagnostic_message_wrong_target_address_is_ignored() {
        let mut client = spawn_handler(test_conn_config(), MockDiagHandler::ok_read(0xF190)).await;

        client
            .write_all(&make_doip_frame(
                PayloadType::RoutingActivationRequest,
                &routing_activation_payload(0x0E00),
            ))
            .await
            .expect("write activation");
        read_doip_frame(&mut client).await;

        let uds = [service_ids::READ_DATA_BY_IDENTIFIER, 0xF1, 0x90];
        client
            .write_all(&make_doip_frame(
                PayloadType::DiagnosticMessage,
                &diag_msg_payload(0x0E00, 0xFFFF, &uds),
            ))
            .await
            .expect("write wrong-target diag");
        client.shutdown().await.expect("shutdown");

        let mut buf = [0u8; 64];
        let n = client.read(&mut buf).await.expect("read");
        assert_eq!(n, 0, "wrong-target message must be silently dropped");
    }

    #[tokio::test]
    async fn rdbi_request_dispatched_to_diag_handler() {
        let did: u16 = 0xF190;
        let ecu_addr = ecu_addr();
        let source_addr: u16 = 0x0E00;
        let mut client = spawn_handler(test_conn_config(), MockDiagHandler::ok_read(did)).await;

        client
            .write_all(&make_doip_frame(
                PayloadType::RoutingActivationRequest,
                &routing_activation_payload(source_addr),
            ))
            .await
            .expect("write activation");
        read_doip_frame(&mut client).await;

        let uds = [service_ids::READ_DATA_BY_IDENTIFIER, 0xF1, 0x90];
        client
            .write_all(&make_doip_frame(
                PayloadType::DiagnosticMessage,
                &diag_msg_payload(source_addr, ecu_addr, &uds),
            ))
            .await
            .expect("write RDBI");

        let response = read_doip_frame(&mut client).await;
        let uds_resp = response.payload.get(4..).expect("uds bytes");
        assert_eq!(
            uds_resp.first().copied(),
            Some(service_ids::READ_DATA_BY_IDENTIFIER | service_ids::POSITIVE_RESPONSE_BITMASK),
        );
    }

    #[tokio::test]
    async fn wdbi_request_dispatched_to_diag_handler() {
        let did: u16 = 0xF190;
        let ecu_addr = ecu_addr();
        let source_addr: u16 = 0x0E00;
        let write_resp = vec![
            service_ids::WRITE_DATA_BY_IDENTIFIER | service_ids::POSITIVE_RESPONSE_BITMASK,
            0xF1,
            0x90,
        ];
        let mut client =
            spawn_handler(test_conn_config(), MockDiagHandler::with_responses(vec![], write_resp))
                .await;

        client
            .write_all(&make_doip_frame(
                PayloadType::RoutingActivationRequest,
                &routing_activation_payload(source_addr),
            ))
            .await
            .expect("write activation");
        read_doip_frame(&mut client).await;

        let uds = [
            service_ids::WRITE_DATA_BY_IDENTIFIER,
            (did >> 8) as u8,
            (did & 0xFF) as u8,
            0xAB,
        ];
        client
            .write_all(&make_doip_frame(
                PayloadType::DiagnosticMessage,
                &diag_msg_payload(source_addr, ecu_addr, &uds),
            ))
            .await
            .expect("write WDBI");

        let response = read_doip_frame(&mut client).await;
        let uds_resp = response.payload.get(4..).expect("uds bytes");
        assert_eq!(
            uds_resp.first().copied(),
            Some(service_ids::WRITE_DATA_BY_IDENTIFIER | service_ids::POSITIVE_RESPONSE_BITMASK),
        );
    }

    #[tokio::test]
    async fn uds_payload_too_short_returns_nrc_13() {
        let ecu_addr = ecu_addr();
        let source_addr: u16 = 0x0E00;
        let mut client = spawn_handler(test_conn_config(), MockDiagHandler::ok_read(0xF190)).await;

        client
            .write_all(&make_doip_frame(
                PayloadType::RoutingActivationRequest,
                &routing_activation_payload(source_addr),
            ))
            .await
            .expect("write activation");
        read_doip_frame(&mut client).await;

        let uds = [service_ids::READ_DATA_BY_IDENTIFIER]; // only 1 byte
        client
            .write_all(&make_doip_frame(
                PayloadType::DiagnosticMessage,
                &diag_msg_payload(source_addr, ecu_addr, &uds),
            ))
            .await
            .expect("write short UDS");

        let response = read_doip_frame(&mut client).await;
        let uds_resp = response.payload.get(4..).expect("uds bytes");
        assert_eq!(uds_resp.first().copied(), Some(0x7F));
        assert_eq!(
            uds_resp.get(2).copied(),
            Some(u8::from(Nrc::IncorrectMessageLengthOrInvalidFormat)),
        );
    }

    #[tokio::test]
    async fn unknown_sid_returns_nrc_11_service_not_supported() {
        let ecu_addr = ecu_addr();
        let source_addr: u16 = 0x0E00;
        let mut client = spawn_handler(test_conn_config(), MockDiagHandler::ok_read(0xF190)).await;

        client
            .write_all(&make_doip_frame(
                PayloadType::RoutingActivationRequest,
                &routing_activation_payload(source_addr),
            ))
            .await
            .expect("write activation");
        read_doip_frame(&mut client).await;

        let uds = [0xFF, 0x00, 0x00];
        client
            .write_all(&make_doip_frame(
                PayloadType::DiagnosticMessage,
                &diag_msg_payload(source_addr, ecu_addr, &uds),
            ))
            .await
            .expect("write unknown SID");

        let response = read_doip_frame(&mut client).await;
        let uds_resp = response.payload.get(4..).expect("uds bytes");
        assert_eq!(uds_resp.first().copied(), Some(0x7F));
        assert_eq!(uds_resp.get(1).copied(), Some(0xFF), "echoed SID");
        assert_eq!(
            uds_resp.get(2).copied(),
            Some(u8::from(Nrc::ServiceNotSupported)),
        );
    }

    // The two DoIP framing unit tests (invalid header / short buffer) are in
    // `frame_buffer.rs` where the framing logic lives.

    /// ISO 13400-2 routing activation response code: success — mirrored here
    /// for test assertions without exposing the internal constant.
    const ROUTING_ACTIVATION_SUCCESS: u8 = 0x10;
}
