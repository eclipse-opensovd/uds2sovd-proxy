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

//! Diagnostic message request handler (ISO 13400-2 payload type 0x8001).
//!
//! Guards: routing must be activated; target address must match the configured
//! ECU logical address; source address must match the activated session.
//! On success the UDS payload is forwarded to [`UdsDispatcher`] and the
//! response is wrapped in a `DiagnosticMessage` frame.

use tracing::{debug, warn};
use uds::Result;

use crate::{
    message::{DiagnosticMessage, DoIpMessage, PayloadType},
    session::Session,
};

use super::payload_handler::{HandlerContext, PayloadHandler};

/// Handles `DiagnosticMessage` (0x8001) frames.
pub(super) struct DiagnosticMessageHandler;

#[async_trait::async_trait]
impl PayloadHandler for DiagnosticMessageHandler {
    fn handles(&self, pt: PayloadType) -> bool {
        pt == PayloadType::DiagnosticMessage
    }

    async fn handle(
        &self,
        msg: &DoIpMessage,
        session: &mut Session,
        ctx: &HandlerContext,
    ) -> Result<Vec<DoIpMessage>> {
        if !session.is_activated() {
            warn!("Received diagnostic message before routing activation");
            return Ok(vec![]);
        }

        let Ok(diag_msg) = DiagnosticMessage::try_from(msg.payload.as_slice()) else {
            warn!("Invalid diagnostic message");
            return Ok(vec![]);
        };

        debug!(
            "Diagnostic message: SA=0x{:04X}, TA=0x{:04X}, {} bytes",
            diag_msg.source_address,
            diag_msg.target_address,
            diag_msg.user_data.len(),
        );

        let expected_target = ctx.conn_config.ecu_logical_address;
        if diag_msg.target_address != expected_target {
            warn!(
                "Ignoring diagnostic message for unexpected target 0x{:04X} (expected 0x{:04X})",
                diag_msg.target_address, expected_target,
            );
            return Ok(vec![]);
        }

        if !session.is_activated_for(diag_msg.source_address) {
            warn!(
                "Ignoring diagnostic message from non-activated source 0x{:04X}",
                diag_msg.source_address,
            );
            return Ok(vec![]);
        }

        let uds_response = ctx.dispatcher.dispatch(&diag_msg.user_data).await;
        if uds_response.is_empty() {
            debug!(
                "UDS response suppressed for source 0x{:04X}",
                diag_msg.source_address,
            );
            return Ok(vec![]);
        }

        let response_payload: Vec<u8> = DiagnosticMessage {
            source_address: ctx.conn_config.source_address,
            target_address: diag_msg.source_address,
            user_data: uds_response,
        }
        .into();
        Ok(vec![DoIpMessage::new(
            PayloadType::DiagnosticMessage,
            response_payload,
        )])
    }
}
