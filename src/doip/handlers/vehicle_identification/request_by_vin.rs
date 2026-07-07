// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 The Contributors to Eclipse OpenSOVD (see CONTRIBUTORS)
//
// See the NOTICE file(s) distributed with this work for additional
// information regarding copyright ownership.
//
// This program and the accompanying materials are made available under the
// terms of the Apache License Version 2.0 which is available at
// https://www.apache.org/licenses/LICENSE-2.0

//! Handler for VIN-filtered vehicle-identification requests.

use super::utils::create_vi_response;
use crate::config::EcuConfig;
use crate::doip::{
    PayloadHandler,
    constants::VIN_LEN,
    error::Error,
    message::{Response, UdpPayloadType, UdpRequest},
    types::{LogicalAddress, Vin},
};

/// Handles `VehicleIdentificationRequestWithVin` messages.
pub struct IdentifyVehicleByVinHandler {
    ecu_config: EcuConfig,
    logical_address: LogicalAddress,
}

impl IdentifyVehicleByVinHandler {
    /// Creates a handler from ECU identity values and the server logical address.
    pub fn new(ecu_config: EcuConfig, logical_address: LogicalAddress) -> Self {
        Self {
            ecu_config,
            logical_address,
        }
    }
}

impl PayloadHandler<UdpPayloadType, UdpRequest> for IdentifyVehicleByVinHandler {
    fn payload_type(&self) -> UdpPayloadType {
        UdpPayloadType::VehicleIdentificationRequestWithVin
    }

    fn handle(&self, udp_request: UdpRequest) -> Result<Response, Error> {
        if udp_request.payload().len() != VIN_LEN {
            return Err(Error::InvalidPayloadLength {
                expected: VIN_LEN as u32,
                actual: udp_request.payload().len(),
            });
        }
        let mut bytes = [0u8; 17];
        bytes.copy_from_slice(udp_request.payload());
        if Vin::new(bytes) != self.ecu_config.vin() {
            return Err(Error::VinNotMatched);
        }
        Ok(create_vi_response(&self.ecu_config, self.logical_address))
    }
}

#[cfg(test)]
mod tests {
    use super::super::utils::fixtures::*;
    use super::*;

    fn handler() -> IdentifyVehicleByVinHandler {
        IdentifyVehicleByVinHandler::new(test_ecu_config(), TEST_ADDR)
    }

    #[test]
    fn matching_vin_returns_announcement() {
        let req = UdpRequest::new(
            UdpPayloadType::VehicleIdentificationRequestWithVin,
            TEST_VIN.as_bytes().to_vec(),
        );
        assert!(handler().handle(req).is_ok());
    }

    #[test]
    fn non_matching_vin_returns_no_match() {
        let req = UdpRequest::new(
            UdpPayloadType::VehicleIdentificationRequestWithVin,
            NON_MATCHING_VIN.as_bytes().to_vec(),
        );
        assert!(matches!(handler().handle(req), Err(Error::VinNotMatched)));
    }

    #[test]
    fn wrong_length_returns_error() {
        let req = UdpRequest::new(
            UdpPayloadType::VehicleIdentificationRequestWithVin,
            vec![0x00; 3], // 3 bytes — less than required 17
        );
        assert!(matches!(
            handler().handle(req),
            Err(Error::InvalidPayloadLength {
                expected: 17,
                actual: 3
            })
        ));
    }
    #[test]
    fn payload_too_long_returns_error() {
        let req = UdpRequest::new(
            UdpPayloadType::VehicleIdentificationRequestWithVin,
            vec![0x00; 18], // 18 bytes — more than required 17
        );
        assert!(matches!(
            handler().handle(req),
            Err(Error::InvalidPayloadLength {
                expected: 17,
                actual: 18
            })
        ));
    }
}
