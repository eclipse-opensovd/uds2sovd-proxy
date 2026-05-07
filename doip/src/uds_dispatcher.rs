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

//! UDS service dispatch.
//!
//! [`UdsDispatcher`] takes a raw UDS byte slice, validates the minimum length,
//! parses the SID, and routes the request to the appropriate [`DiagHandler`]
//! method.  It is the boundary between the `DoIP` transport layer (framing,
//! session, addressing) and the UDS semantic layer (service identification,
//! DID extraction, NRC construction).
//!
//! # Single responsibility
//!
//! `UdsDispatcher` knows only about UDS; it has no opinion about TCP, `DoIP`
//! headers, or session state.  `ConnectionHandler` knows only about `DoIP`
//! transport; it delegates all UDS decisions here.

use std::sync::Arc;

use uds::{
    DataIdentifier, DiagHandler, ReadDid, RequestHandler, UdsSid, WriteDid,
    error::{Nrc, UdsError},
    uds_service_ids as service_ids,
};
use tracing::{debug, error, info};

/// Minimum total UDS payload to attempt service dispatch: SID (1) + DID (2).
const MIN_DISPATCH_LENGTH: usize = 3;

/// Minimum data bytes after the SID for a `WriteDataByIdentifier` request:
/// DID high (1) + DID low (1) + at least one data byte (1).
const MIN_WDBI_DATA_LENGTH: usize = 3;

/// Minimum data bytes after the SID for a `ReadDataByIdentifier` request:
/// DID high (1) + DID low (1).
const MIN_RDBI_DATA_LENGTH: usize = 2;

/// Service ID used in the NRC frame when the SID cannot be determined
/// (e.g. the request is too short to contain any bytes).
const UNKNOWN_SERVICE_ID: u8 = 0x00;

// ── UdsMessage ───────────────────────────────────────────────────────────────

/// Parsed UDS message: a service identifier and the remaining data bytes.
#[derive(Debug, Clone)]
pub(crate) struct UdsMessage {
    /// UDS Service Identifier byte (e.g. 0x22 = `ReadDataByIdentifier`).
    pub(crate) service_id: u8,
    /// Bytes following the SID (sub-function, DID, request data, etc.).
    pub(crate) data: Vec<u8>,
}

impl TryFrom<&[u8]> for UdsMessage {
    type Error = UdsError;

    /// Parse a UDS message from raw bytes.
    ///
    /// The first byte is interpreted as the SID; the rest becomes `data`.
    ///
    /// # Errors
    ///
    /// Returns [`UdsError::InvalidLength`] if the slice is empty.
    fn try_from(bytes: &[u8]) -> std::result::Result<Self, Self::Error> {
        let &first = bytes.first().ok_or(UdsError::InvalidLength {
            expected: 1,
            actual: 0,
        })?;

        Ok(Self {
            service_id: first,
            data: bytes.get(1..).unwrap_or_default().to_vec(),
        })
    }
}

impl UdsMessage {
    /// Build a 3-byte UDS negative response: `[0x7F, SID, NRC]`.
    #[must_use]
    pub(crate) fn build_negative_response(&self, nrc: Nrc) -> Vec<u8> {
        nrc.response_for(self.service_id).to_vec()
    }

    /// Extract a 16-bit DID from the first two data bytes.
    pub(crate) fn extract_did(&self) -> Option<u16> {
        let &hi = self.data.first()?;
        let &lo = self.data.get(1)?;
        Some(u16::from_be_bytes([hi, lo]))
    }
}

/// Routes raw UDS byte slices to the appropriate [`DiagHandler`] method.
///
/// This type owns all UDS-semantic knowledge: minimum lengths per service,
/// DID extraction, NRC selection, and SID dispatch.  It has no knowledge of
/// No `DoIP` framing, TCP I/O, or session state — those are concerns of
/// [`ConnectionHandler`](crate::handler::ConnectionHandler).
pub(crate) struct UdsDispatcher {
    diag_handler: Arc<dyn DiagHandler>,
}

impl UdsDispatcher {
    /// Create a new dispatcher backed by the given diagnostic handler.
    pub(crate) fn new(diag_handler: Arc<dyn DiagHandler>) -> Self {
        Self { diag_handler }
    }

    /// Dispatch a raw UDS request and return the UDS response bytes.
    ///
    /// All protocol-level errors are encoded as UDS negative responses so
    /// the `DoIP` transport always has bytes to send back.  I/O or backend
    /// failures that are unrecoverable are also encoded as negative responses
    /// with `GeneralProgrammingFailure` so the transport layer never has to
    /// decide what to do with a UDS error.
    ///
    /// Returns an empty `Vec` only when the response should be suppressed
    /// (currently never — all inputs receive a response).
    pub(crate) async fn dispatch(&self, uds_data: &[u8]) -> Vec<u8> {
        if uds_data.len() < MIN_DISPATCH_LENGTH {
            error!(
                "UDS request too short: {} byte(s), minimum is {}",
                uds_data.len(),
                MIN_DISPATCH_LENGTH,
            );
            return Nrc::IncorrectMessageLengthOrInvalidFormat
                .response_for(UNKNOWN_SERVICE_ID)
                .to_vec();
        }

        if let Some(&sid) = uds_data.first() {
            info!(
                "UDS request SID=0x{:02X}, payload_len={} bytes",
                sid,
                uds_data.len(),
            );
        }
        debug!("UDS request payload: {:02X?}", uds_data);

        let uds_msg = match UdsMessage::try_from(uds_data) {
            Ok(msg) => msg,
            Err(e) => {
                error!("Failed to parse UDS message: {}", e);
                return Nrc::IncorrectMessageLengthOrInvalidFormat
                    .response_for(UNKNOWN_SERVICE_ID)
                    .to_vec();
            }
        };

        match UdsSid::try_from(uds_msg.service_id) {
            Ok(UdsSid::ReadDataByIdentifier) => self.handle_rdbi(&uds_msg).await,
            Ok(UdsSid::WriteDataByIdentifier) => self.handle_wdbi(&uds_msg).await,
            // TODO(uds): Add DiagnosticSessionControl (0x10) and TesterPresent (0x3E)
            // handling — both are required for compliant UDS communication.
            // TesterPresent responds with a positive response; session control
            // forwards to the SOVD gateway modes API.
            _ => {
                info!("Unsupported service: 0x{:02X}", uds_msg.service_id);
                uds_msg.build_negative_response(Nrc::ServiceNotSupported)
            }
        }
    }

    /// Handle a `ReadDataByIdentifier` (SID 0x22) request.
    async fn handle_rdbi(&self, uds_msg: &UdsMessage) -> Vec<u8> {
        if uds_msg.data.len() < MIN_RDBI_DATA_LENGTH {
            error!("Invalid read request — missing DID");
            return uds_msg.build_negative_response(Nrc::IncorrectMessageLengthOrInvalidFormat);
        }

        let Some(did) = uds_msg.extract_did() else {
            return uds_msg.build_negative_response(Nrc::IncorrectMessageLengthOrInvalidFormat);
        };

        let raw = {
            let mut req = vec![service_ids::READ_DATA_BY_IDENTIFIER];
            req.extend_from_slice(uds_msg.data.get(..MIN_RDBI_DATA_LENGTH).unwrap_or_default());
            req
        };
        let req = ReadDid { did: DataIdentifier::new(did), raw };

        match req.handle(&*self.diag_handler).await {
            Ok(response) => response,
            Err(e) => {
                error!("[UDS2SOVD] RDBI failed: {}", e);
                uds_msg.build_negative_response(Nrc::GeneralProgrammingFailure)
            }
        }
    }

    /// Handle a `WriteDataByIdentifier` (SID 0x2E) request.
    async fn handle_wdbi(&self, uds_msg: &UdsMessage) -> Vec<u8> {
        if uds_msg.data.len() < MIN_WDBI_DATA_LENGTH {
            error!("Invalid write request — missing DID or data");
            return uds_msg.build_negative_response(Nrc::IncorrectMessageLengthOrInvalidFormat);
        }

        let Some(did) = uds_msg.extract_did() else {
            return uds_msg.build_negative_response(Nrc::IncorrectMessageLengthOrInvalidFormat);
        };

        let raw = {
            let mut req = vec![service_ids::WRITE_DATA_BY_IDENTIFIER];
            req.extend_from_slice(&uds_msg.data);
            req
        };
        let req = WriteDid { did: DataIdentifier::new(did), raw };

        match req.handle(&*self.diag_handler).await {
            Ok(response) => response,
            Err(e) => {
                error!("[UDS2SOVD] WDBI failed: {}", e);
                uds_msg.build_negative_response(Nrc::GeneralProgrammingFailure)
            }
        }
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use uds::{
        DiagHandler, ReadDid, Result, WriteDid, assert_nrc, assert_positive_response,
        uds_service_ids as service_ids,
    };

    use super::*;

    struct EchoHandler;

    #[async_trait::async_trait]
    impl DiagHandler for EchoHandler {
        async fn read_did(&self, req: &ReadDid) -> Result<Vec<u8>> {
            Ok(vec![
                service_ids::READ_DATA_BY_IDENTIFIER | service_ids::POSITIVE_RESPONSE_BITMASK,
                (req.did.value() >> 8) as u8,
                (req.did.value() & 0xFF) as u8,
            ])
        }

        async fn write_did(&self, req: &WriteDid) -> Result<Vec<u8>> {
            Ok(vec![
                service_ids::WRITE_DATA_BY_IDENTIFIER | service_ids::POSITIVE_RESPONSE_BITMASK,
                (req.did.value() >> 8) as u8,
                (req.did.value() & 0xFF) as u8,
            ])
        }
    }

    fn dispatcher() -> UdsDispatcher {
        UdsDispatcher::new(std::sync::Arc::new(EchoHandler))
    }

    #[tokio::test]
    async fn dispatch_rdbi_returns_positive_response() {
        let resp = dispatcher()
            .dispatch(&[service_ids::READ_DATA_BY_IDENTIFIER, 0xF1, 0x90])
            .await;
        assert_positive_response!(resp, 0x62, 0xF1, 0x90);
    }

    #[tokio::test]
    async fn dispatch_wdbi_returns_positive_response() {
        let resp = dispatcher()
            .dispatch(&[service_ids::WRITE_DATA_BY_IDENTIFIER, 0xF1, 0x90, 0xAB])
            .await;
        assert_positive_response!(resp, 0x6E, 0xF1, 0x90);
    }

    #[tokio::test]
    async fn dispatch_too_short_returns_nrc_13() {
        // Only 1 byte — below MIN_DISPATCH_LENGTH (3); SID unknown → 0x00
        let resp = dispatcher()
            .dispatch(&[service_ids::READ_DATA_BY_IDENTIFIER])
            .await;
        assert_nrc!(resp, 0x00, 0x13);
    }

    #[tokio::test]
    async fn dispatch_unknown_sid_returns_nrc_11() {
        let resp = dispatcher().dispatch(&[0xFF, 0x00, 0x00]).await;
        assert_nrc!(resp, 0xFF, 0x11);
    }

    #[tokio::test]
    async fn dispatch_rdbi_too_short_returns_nrc_incorrect_length() {
        // SID present but only 1 data byte (total 2) — below MIN_DISPATCH_LENGTH (3)
        let resp = dispatcher()
            .dispatch(&[service_ids::READ_DATA_BY_IDENTIFIER, 0xF1])
            .await;
        assert_nrc!(resp, 0x00, 0x13);
    }

    #[tokio::test]
    async fn dispatch_wdbi_missing_data_byte_returns_nrc_13() {
        // SID + 2 DID bytes — no data byte; data slice len 2 < MIN_WDBI_DATA_LENGTH (3)
        let resp = dispatcher()
            .dispatch(&[service_ids::WRITE_DATA_BY_IDENTIFIER, 0xF1, 0x90])
            .await;
        assert_nrc!(resp, service_ids::WRITE_DATA_BY_IDENTIFIER, 0x13);
    }

    #[tokio::test]
    async fn dispatch_empty_returns_nrc_13() {
        let resp = dispatcher().dispatch(&[]).await;
        assert_nrc!(resp, 0x00, 0x13);
    }

    #[tokio::test]
    async fn dispatch_two_byte_returns_nrc_13() {
        // Exactly one byte below MIN_DISPATCH_LENGTH
        let resp = dispatcher().dispatch(&[0x22, 0xF1]).await;
        assert_nrc!(resp, 0x00, 0x13);
    }

    #[tokio::test]
    async fn dispatch_rdbi_boundary_exactly_three_bytes() {
        // Exactly MIN_DISPATCH_LENGTH — should succeed
        let resp = dispatcher()
            .dispatch(&[service_ids::READ_DATA_BY_IDENTIFIER, 0xF1, 0x90])
            .await;
        assert_positive_response!(resp, 0x62, 0xF1, 0x90);
    }

    #[tokio::test]
    async fn dispatch_rdbi_extra_bytes_are_ignored() {
        // Dispatcher trims to DID only for RDBI
        let resp = dispatcher()
            .dispatch(&[service_ids::READ_DATA_BY_IDENTIFIER, 0xF1, 0x90, 0x00, 0x00])
            .await;
        assert_positive_response!(resp, 0x62, 0xF1, 0x90);
    }

    #[tokio::test]
    async fn uds_message_parses_correctly() {
        let msg = UdsMessage::try_from([0x22u8, 0xF1, 0x90].as_slice()).expect("valid");
        assert_eq!(msg.service_id, 0x22);
        assert_eq!(msg.data, vec![0xF1, 0x90]);
        assert_eq!(msg.extract_did(), Some(0xF190));
    }

    #[test]
    fn uds_message_single_byte_has_empty_data() {
        let msg = UdsMessage::try_from([0x3Eu8].as_slice()).expect("valid single-byte");
        assert_eq!(msg.service_id, 0x3E);
        assert!(msg.data.is_empty());
        assert_eq!(msg.extract_did(), None);
    }

    #[test]
    fn uds_message_empty_returns_error() {
        assert!(UdsMessage::try_from([0u8; 0].as_slice()).is_err());
    }

    #[test]
    fn uds_message_negative_response_correct_bytes() {
        let msg = UdsMessage { service_id: 0x22, data: vec![] };
        assert_eq!(
            msg.build_negative_response(Nrc::RequestOutOfRange),
            vec![0x7F, 0x22, 0x31]
        );
    }

    #[test]
    fn uds_message_extract_did_returns_none_with_one_data_byte() {
        let msg = UdsMessage { service_id: 0x22, data: vec![0xF1] };
        assert_eq!(msg.extract_did(), None);
    }

    #[test]
    fn uds_message_extract_did_combines_bytes_big_endian() {
        let msg = UdsMessage { service_id: 0x22, data: vec![0x12, 0x34] };
        assert_eq!(msg.extract_did(), Some(0x1234));
    }
}
