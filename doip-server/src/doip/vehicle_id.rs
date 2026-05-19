/*
 * Copyright (c) 2026 The Contributors to Eclipse OpenSOVD (see CONTRIBUTORS)
 *
 * See the NOTICE file(s) distributed with this work for additional
 * information regarding copyright ownership.
 *
 * This program and the accompanying materials are made available under the
 * terms of the Apache License Version 2.0 which is available at
 * https://www.apache.org/licenses/LICENSE-2.0
 *
 * SPDX-License-Identifier: Apache-2.0
 */

//! Vehicle Identification handlers (ISO 13400-2:2019)

use bytes::{BufMut, BytesMut};
use tracing::error;

use super::{DoipParseable, DoipSerializable, check_min_len, parse_fixed_slice, too_short};
use crate::DoipError;
use crate::Result;

// Wire-format field lengths for VehicleIdentificationResponse (ISO 13400-2:2019)
const VIN_LEN: usize = 17;
const LOGICAL_ADDR_LEN: usize = 2;
const EID_LEN: usize = 6;
const GID_LEN: usize = 6;
const FURTHER_ACTION_LEN: usize = 1;

// Pre-computed byte offsets derived from field layout
const VIN_END: usize = VIN_LEN; // 17
const ADDR_START: usize = VIN_END; // 17
const ADDR_END: usize = ADDR_START + LOGICAL_ADDR_LEN; // 19
const EID_START: usize = ADDR_END; // 19
const EID_END: usize = EID_START + EID_LEN; // 25
const GID_START: usize = EID_END; // 25
const GID_END: usize = GID_START + GID_LEN; // 31
const FURTHER_ACTION_IDX: usize = GID_END; // 31
const SYNC_STATUS_IDX: usize = FURTHER_ACTION_IDX + FURTHER_ACTION_LEN; // 32

/// Vehicle Identification Request (payload type `0x0001`) – broadcast with no filter criteria.
///
/// The `DoIP` entity responds with a Vehicle Identification Response containing VIN, EID, and GID.
///
/// `Clone` is derived because [`DoipPayload`](super::payload::DoipPayload) wraps this type and itself derives `Clone`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VehicleIdRequest;

/// Vehicle Identification Request filtered by EID (payload type `0x0002`).
///
/// Only the `DoIP` entity with a matching 6-byte EID should respond.
///
/// `Clone` is derived because [`DoipPayload`](super::payload::DoipPayload) wraps this type and itself derives `Clone`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VehicleIdRequestWithEid {
    eid: [u8; EID_LEN],
}

impl VehicleIdRequestWithEid {
    /// Fixed wire-format length of a Vehicle Identification Request with EID
    /// payload (6-byte EID filter).
    pub(crate) const PAYLOAD_LEN: usize = EID_LEN;

    /// Create a new Vehicle Identification Request filtered by the given 6-byte EID.
    #[must_use]
    pub fn new(eid: [u8; EID_LEN]) -> Self {
        Self { eid }
    }

    /// The EID filter value
    #[must_use]
    pub fn eid(&self) -> &[u8; EID_LEN] {
        &self.eid
    }
}

/// Vehicle Identification Request filtered by VIN (payload type `0x0003`).
///
/// Only the `DoIP` entity with a matching 17-byte VIN should respond.
///
/// `Clone` is derived because [`DoipPayload`](super::payload::DoipPayload) wraps this type and itself derives `Clone`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VehicleIdRequestWithVin {
    vin: [u8; VIN_LEN],
}

impl VehicleIdRequestWithVin {
    /// Fixed wire-format length of a Vehicle Identification Request with VIN payload (17-byte VIN).
    pub(crate) const PAYLOAD_LEN: usize = VIN_LEN;

    /// Create a new Vehicle Identification Request filtered by the given 17-byte VIN.
    #[must_use]
    pub fn new(vin: [u8; VIN_LEN]) -> Self {
        Self { vin }
    }

    /// The VIN filter value as bytes
    #[must_use]
    pub fn vin(&self) -> &[u8; VIN_LEN] {
        &self.vin
    }

    /// The VIN filter value as a UTF-8 string (lossy – non-UTF-8 bytes replaced with `�`).
    #[must_use]
    pub fn vin_string(&self) -> String {
        String::from_utf8_lossy(&self.vin).to_string()
    }
}

/// Further action codes per ISO 13400-2:2019 Table 23.
///
/// Indicates whether the tester must take additional steps (e.g., routing
/// activation) after identification.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum FurtherAction {
    NoFurtherAction = 0x00,
    RoutingActivationRequired = 0x10,
}

impl TryFrom<u8> for FurtherAction {
    type Error = u8;
    fn try_from(value: u8) -> std::result::Result<Self, Self::Error> {
        match value {
            0x00 => Ok(Self::NoFurtherAction),
            0x10 => Ok(Self::RoutingActivationRequired),
            other => Err(other),
        }
    }
}

impl From<FurtherAction> for u8 {
    fn from(action: FurtherAction) -> Self {
        action as Self
    }
}

/// GID synchronization status per ISO 13400-2:2019 Table 22.
///
/// Indicates whether the `DoIP` entity's Group ID is synchronized across all ECUs.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum GidSyncStatus {
    Synchronized = 0x00,
    NotSynchronized = 0x10,
}

impl TryFrom<u8> for GidSyncStatus {
    type Error = u8;
    fn try_from(value: u8) -> std::result::Result<Self, Self::Error> {
        match value {
            0x00 => Ok(Self::Synchronized),
            0x10 => Ok(Self::NotSynchronized),
            other => Err(other),
        }
    }
}

impl From<GidSyncStatus> for u8 {
    fn from(status: GidSyncStatus) -> Self {
        status as Self
    }
}

/// Vehicle Identification Response (payload type `0x0004`) – sent by the `DoIP` entity.
///
/// Contains VIN, logical address, EID, GID, further action code, and optional sync status.
///
/// # Wire Format
/// VIN(17) + LogicalAddr(2) + EID(6) + GID(6) + FurtherAction(1) + optional GidSyncStatus(1)
///
/// `Clone` is derived because [`DoipPayload`](super::payload::DoipPayload) wraps this type and itself derives `Clone`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VehicleIdResponse {
    vin: [u8; VIN_LEN],
    logical_address: u16,
    eid: [u8; EID_LEN],
    gid: [u8; GID_LEN],
    further_action: FurtherAction,
    sync_status: Option<GidSyncStatus>,
}

impl VehicleIdResponse {
    /// Minimum wire-format length of a Vehicle Identification Response payload
    /// (32 bytes: VIN(17) + LogicalAddr(2) + EID(6) + GID(6) + FurtherAction(1)).
    pub(crate) const MIN_LEN: usize = SYNC_STATUS_IDX;
    /// Maximum wire-format length of a Vehicle Identification Response payload
    /// (33 bytes: adds optional GidSyncStatus(1)).
    pub(crate) const MAX_LEN: usize = SYNC_STATUS_IDX + 1;

    /// Create a new Vehicle Identification Response with the required fields.
    ///
    /// `further_action` defaults to [`FurtherAction::NoFurtherAction`]; use
    /// [`with_routing_required`](Self::with_routing_required) to override.
    #[must_use]
    pub fn new(
        vin: [u8; VIN_LEN],
        logical_address: u16,
        eid: [u8; EID_LEN],
        gid: [u8; GID_LEN],
    ) -> Self {
        Self {
            vin,
            logical_address,
            eid,
            gid,
            further_action: FurtherAction::NoFurtherAction,
            sync_status: None,
        }
    }

    /// Set `FurtherAction` to `RoutingActivationRequired` (ISO 13400-2:2019 Table 23 – 0x10).
    #[must_use]
    pub fn with_routing_required(mut self) -> Self {
        self.further_action = FurtherAction::RoutingActivationRequired;
        self
    }

    /// Attach an optional GID synchronization status byte to the response
    /// (ISO 13400-2:2019 Table 22).
    #[must_use]
    pub fn with_sync_status(mut self, status: GidSyncStatus) -> Self {
        self.sync_status = Some(status);
        self
    }

    /// Returns the VIN as a UTF-8 string (lossy – non-UTF-8 bytes replaced with `�`).
    #[must_use]
    pub fn vin_string(&self) -> String {
        String::from_utf8_lossy(&self.vin).to_string()
    }

    /// The raw VIN bytes.
    #[must_use]
    pub fn vin(&self) -> &[u8; VIN_LEN] {
        &self.vin
    }

    /// The logical address of the `DoIP` entity.
    #[must_use]
    pub fn logical_address(&self) -> u16 {
        self.logical_address
    }

    /// The 6-byte Entity Identifier.
    #[must_use]
    pub fn eid(&self) -> &[u8; EID_LEN] {
        &self.eid
    }

    /// The 6-byte Group Identifier.
    #[must_use]
    pub fn gid(&self) -> &[u8; GID_LEN] {
        &self.gid
    }

    /// The further action code.
    #[must_use]
    pub fn further_action(&self) -> FurtherAction {
        self.further_action
    }

    /// The optional GID synchronization status.
    #[must_use]
    pub fn sync_status(&self) -> Option<GidSyncStatus> {
        self.sync_status
    }
}

impl DoipParseable for VehicleIdRequest {
    fn parse(payload: &[u8]) -> Result<Self> {
        if !payload.is_empty() {
            return Err(DoipError::UnexpectedPayload {
                actual: payload.len(),
            });
        }
        Ok(Self)
    }
}

impl DoipParseable for VehicleIdRequestWithEid {
    fn parse(payload: &[u8]) -> Result<Self> {
        let eid: [u8; Self::PAYLOAD_LEN] = parse_fixed_slice(payload, "VehicleIdRequestWithEid")?;
        Ok(Self { eid })
    }
}

impl DoipParseable for VehicleIdRequestWithVin {
    fn parse(payload: &[u8]) -> Result<Self> {
        let vin: [u8; Self::PAYLOAD_LEN] = parse_fixed_slice(payload, "VehicleIdRequestWithVin")?;
        Ok(Self { vin })
    }
}

impl DoipParseable for VehicleIdResponse {
    fn parse(payload: &[u8]) -> Result<Self> {
        if let Err(e) = check_min_len(payload, Self::MIN_LEN) {
            error!(error = %e, "VehicleId Response parse failed");
            return Err(e);
        }

        let vin: [u8; VIN_LEN] = payload
            .get(..VIN_END)
            .and_then(|s| s.try_into().ok())
            .ok_or_else(|| too_short(payload, Self::MIN_LEN))?;

        let addr_bytes: [u8; LOGICAL_ADDR_LEN] = payload
            .get(ADDR_START..ADDR_END)
            .and_then(|s| s.try_into().ok())
            .ok_or_else(|| too_short(payload, Self::MIN_LEN))?;
        let logical_address = u16::from_be_bytes(addr_bytes);

        let eid: [u8; EID_LEN] = payload
            .get(EID_START..EID_END)
            .and_then(|s| s.try_into().ok())
            .ok_or_else(|| too_short(payload, Self::MIN_LEN))?;

        let gid: [u8; GID_LEN] = payload
            .get(GID_START..GID_END)
            .and_then(|s| s.try_into().ok())
            .ok_or_else(|| too_short(payload, Self::MIN_LEN))?;

        let further_action_byte = payload
            .get(FURTHER_ACTION_IDX)
            .copied()
            .ok_or_else(|| too_short(payload, Self::MIN_LEN))?;
        let further_action = FurtherAction::try_from(further_action_byte)
            .map_err(DoipError::UnknownFurtherAction)?;

        let sync_status = payload
            .get(SYNC_STATUS_IDX)
            .map(|&b| GidSyncStatus::try_from(b).map_err(DoipError::UnknownSyncStatus))
            .transpose()?;

        Ok(Self {
            vin,
            logical_address,
            eid,
            gid,
            further_action,
            sync_status,
        })
    }
}

impl DoipSerializable for VehicleIdResponse {
    fn serialized_len(&self) -> Option<usize> {
        Some(if self.sync_status.is_some() {
            Self::MAX_LEN
        } else {
            Self::MIN_LEN
        })
    }

    fn write_to(&self, buf: &mut BytesMut) {
        buf.extend_from_slice(&self.vin);
        buf.put_u16(self.logical_address);
        buf.extend_from_slice(&self.eid);
        buf.extend_from_slice(&self.gid);
        buf.put_u8(u8::from(self.further_action));
        if let Some(status) = self.sync_status {
            buf.put_u8(u8::from(status));
        }
    }
}

#[cfg(test)]
#[allow(clippy::indexing_slicing)]
mod tests {
    use super::*;
    use crate::doip::{DoipParseable, DoipSerializable};

    #[test]
    fn parse_basic_request() {
        let req = VehicleIdRequest::parse(&[]).unwrap();
        assert_eq!(req, VehicleIdRequest);
    }

    #[test]
    fn parse_request_with_eid() {
        let payload = [0x00, 0x1A, 0x2B, 0x3C, 0x4D, 0x5E];
        let req = VehicleIdRequestWithEid::parse(&payload).unwrap();
        assert_eq!(req.eid(), &[0x00, 0x1A, 0x2B, 0x3C, 0x4D, 0x5E]);
    }

    #[test]
    fn reject_short_eid_request() {
        let short = [0x00, 0x1A, 0x2B];
        assert!(VehicleIdRequestWithEid::parse(&short).is_err());
    }

    #[test]
    fn parse_request_with_vin() {
        let vin = b"WVWZZZ3CZWE123456";
        let req = VehicleIdRequestWithVin::parse(vin).unwrap();
        assert_eq!(req.vin_string(), "WVWZZZ3CZWE123456");
    }

    #[test]
    fn reject_short_vin_request() {
        let short = b"WVWZZZ";
        assert!(VehicleIdRequestWithVin::parse(short).is_err());
    }

    #[test]
    fn build_basic_response() {
        let vin = *b"WVWZZZ3CZWE123456";
        let eid = [0x00, 0x1A, 0x2B, 0x3C, 0x4D, 0x5E];
        let gid = [0x00, 0x00, 0x00, 0x00, 0x00, 0x01];

        let resp = VehicleIdResponse::new(vin, 0x1000, eid, gid);

        assert_eq!(resp.logical_address(), 0x1000);
        assert_eq!(resp.further_action(), FurtherAction::NoFurtherAction);
        assert!(resp.sync_status().is_none());
    }

    #[test]
    fn build_response_with_routing_required() {
        let vin = *b"WVWZZZ3CZWE123456";
        let eid = [0; 6];
        let gid = [0; 6];

        let resp = VehicleIdResponse::new(vin, 0x1000, eid, gid).with_routing_required();
        assert_eq!(
            resp.further_action(),
            FurtherAction::RoutingActivationRequired
        );
    }

    #[test]
    fn serialize_response_minimal() {
        let vin = *b"WVWZZZ3CZWE123456";
        let eid = [0x00, 0x1A, 0x2B, 0x3C, 0x4D, 0x5E];
        let gid = [0x00, 0x00, 0x00, 0x00, 0x00, 0x01];

        let resp = VehicleIdResponse::new(vin, 0x1000, eid, gid);
        let bytes = resp.to_bytes();

        assert_eq!(bytes.len(), VehicleIdResponse::MIN_LEN);
        assert_eq!(&bytes[..VIN_LEN], b"WVWZZZ3CZWE123456");
        assert_eq!(&bytes[ADDR_START..ADDR_END], &[0x10, 0x00]); // logical address
    }

    #[test]
    fn serialize_response_with_sync() {
        let vin = *b"WVWZZZ3CZWE123456";
        let eid = [0; 6];
        let gid = [0; 6];

        let resp = VehicleIdResponse::new(vin, 0x1000, eid, gid)
            .with_sync_status(GidSyncStatus::Synchronized);
        let bytes = resp.to_bytes();

        assert_eq!(bytes.len(), VehicleIdResponse::MAX_LEN);
        assert_eq!(bytes[SYNC_STATUS_IDX], GidSyncStatus::Synchronized as u8); // sync status
    }

    #[test]
    fn parse_response() {
        let vin = *b"WVWZZZ3CZWE123456";
        let eid = [0x00, 0x1A, 0x2B, 0x3C, 0x4D, 0x5E];
        let gid = [0x00, 0x00, 0x00, 0x00, 0x00, 0x01];

        let original = VehicleIdResponse::new(vin, 0x1000, eid, gid);
        let bytes = original.to_bytes();
        let parsed = VehicleIdResponse::parse(&bytes).unwrap();

        assert_eq!(parsed.vin(), &vin);
        assert_eq!(parsed.logical_address(), 0x1000);
        assert_eq!(parsed.eid(), &eid);
        assert_eq!(parsed.gid(), &gid);
    }

    #[test]
    fn roundtrip_response() {
        let vin = *b"WVWZZZ3CZWE123456";
        let eid = [0x00, 0x1A, 0x2B, 0x3C, 0x4D, 0x5E];
        let gid = [0x00, 0x00, 0x00, 0x00, 0x00, 0x01];

        let original = VehicleIdResponse::new(vin, 0x1000, eid, gid)
            .with_routing_required()
            .with_sync_status(GidSyncStatus::NotSynchronized);

        let bytes = original.to_bytes();
        let parsed = VehicleIdResponse::parse(&bytes).unwrap();

        assert_eq!(original, parsed);
    }
}
