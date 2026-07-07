// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 The Contributors to Eclipse OpenSOVD (see CONTRIBUTORS)
//
// See the NOTICE file(s) distributed with this work for additional
// information regarding copyright ownership.
//
// This program and the accompanying materials are made available under the
// terms of the Apache License Version 2.0 which is available at
// https://www.apache.org/licenses/LICENSE-2.0

use crate::config::EcuConfig;
use crate::doip::{
    PayloadHandler,
    constants::EID_LEN,
    error::Error,
    message::{Response, UdpPayloadType, UdpRequest},
    types::{Eid, LogicalAddress},
};

use super::utils::create_vi_response;

/// Handles `VehicleIdentificationRequestWithEid` messages.
pub struct IdentifyVehicleByEidHandler {
    ecu_config: EcuConfig,
    logical_address: LogicalAddress,
}

impl IdentifyVehicleByEidHandler {
    /// Creates a handler from ECU identity values and the server logical address.
    pub fn new(ecu_config: EcuConfig, logical_address: LogicalAddress) -> Self {
        Self {
            ecu_config,
            logical_address,
        }
    }
}

impl PayloadHandler<UdpPayloadType, UdpRequest> for IdentifyVehicleByEidHandler {
    fn payload_type(&self) -> UdpPayloadType {
        UdpPayloadType::VehicleIdentificationRequestWithEid
    }

    fn handle(&self, udp_request: UdpRequest) -> Result<Response, Error> {
        if udp_request.payload().len() != EID_LEN {
            return Err(Error::InvalidPayloadLength {
                expected: EID_LEN as u32,
                actual: udp_request.payload().len(),
            });
        }
        let requested = Eid::new([
            udp_request.payload()[0],
            udp_request.payload()[1],
            udp_request.payload()[2],
            udp_request.payload()[3],
            udp_request.payload()[4],
            udp_request.payload()[5],
        ]);
        if requested != self.ecu_config.eid() {
            return Err(Error::EIDNotMatched);
        }
        Ok(create_vi_response(&self.ecu_config, self.logical_address))
    }
}

#[cfg(test)]
mod tests {
    use super::super::utils::fixtures::*;
    use super::*;

    fn handler() -> IdentifyVehicleByEidHandler {
        IdentifyVehicleByEidHandler::new(test_ecu_config(), TEST_ADDR)
    }

    #[test]
    fn matching_eid_returns_announcement() {
        let req = UdpRequest::new(
            UdpPayloadType::VehicleIdentificationRequestWithEid,
            TEST_EID.as_bytes().to_vec(),
        );
        assert!(handler().handle(req).is_ok());
    }

    #[test]
    fn non_matching_eid_returns_no_match() {
        let req = UdpRequest::new(
            UdpPayloadType::VehicleIdentificationRequestWithEid,
            NON_MATCHING_EID.as_bytes().to_vec(),
        );
        assert!(matches!(handler().handle(req), Err(Error::EIDNotMatched)));
    }

    #[test]
    fn wrong_length_returns_error() {
        let req = UdpRequest::new(
            UdpPayloadType::VehicleIdentificationRequestWithEid,
            vec![0x00; 3], // 3 bytes — less than required 6
        );
        assert!(matches!(
            handler().handle(req),
            Err(Error::InvalidPayloadLength {
                expected: 6,
                actual: 3
            })
        ));
    }
    #[test]
    fn payload_too_long_returns_error() {
        let req = UdpRequest::new(
            UdpPayloadType::VehicleIdentificationRequestWithEid,
            vec![0x00; 7], // 7 bytes — more than required 6
        );
        assert!(matches!(
            handler().handle(req),
            Err(Error::InvalidPayloadLength {
                expected: 6,
                actual: 7
            })
        ));
    }
}
