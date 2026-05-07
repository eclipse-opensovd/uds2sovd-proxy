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

//! Routing activation request handler (ISO 13400-2 payload type 0x0005).
//!
//! Parses the incoming `RoutingActivationRequest`, activates the session for
//! the tester source address, and returns a `RoutingActivationResponse`
//! (0x0006) with a success code.

use tracing::{info, warn};
use uds::Result;

use crate::{
    message::{DoIpMessage, PayloadType, RoutingActivationRequest},
    session::Session,
};

use super::payload_handler::{HandlerContext, PayloadHandler};

/// ISO 13400-2 routing activation response code: routing activation accepted.
const ROUTING_ACTIVATION_SUCCESS: u8 = 0x10;

/// ISO 13400-2 §7.3.2: four reserved bytes (shall be 0x00000000) that follow the response code.
const ROUTING_ACTIVATION_RESERVED: [u8; 4] = [0x00; 4];

/// Handles `RoutingActivationRequest` (0x0005) frames.
pub(super) struct RoutingActivationHandler;

#[async_trait::async_trait]
impl PayloadHandler for RoutingActivationHandler {
    fn handles(&self, pt: PayloadType) -> bool {
        pt == PayloadType::RoutingActivationRequest
    }

    async fn handle(
        &self,
        msg: &DoIpMessage,
        session: &mut Session,
        ctx: &HandlerContext,
    ) -> Result<Vec<DoIpMessage>> {
        let Ok(req) = RoutingActivationRequest::try_from(msg.payload.as_slice()) else {
            warn!("Invalid routing activation request");
            return Ok(vec![]);
        };

        session.activate(req.source_address);

        // ISO 13400-2 Table 19: source address (2) + entity address (2) +
        // response code (1) + ISO-reserved (4). Minimum 9 bytes total.
        let mut payload = Vec::new();
        payload.extend_from_slice(&req.source_address.to_be_bytes());
        payload.extend_from_slice(&ctx.conn_config.ecu_logical_address.to_be_bytes());
        payload.push(ROUTING_ACTIVATION_SUCCESS);
        payload.extend_from_slice(&ROUTING_ACTIVATION_RESERVED);

        info!(
            "Routing activated for source address 0x{:04X}",
            req.source_address,
        );

        Ok(vec![DoIpMessage::new(
            PayloadType::RoutingActivationResponse,
            payload,
        )])
    }
}
