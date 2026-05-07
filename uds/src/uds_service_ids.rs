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

//! UDS Service Identifier (SID) constants and typed enum — ISO 14229-1.
//!
//! Constants are retained for bitwise operations (response encoding, NRC
//! construction).  The [`UdsSid`] enum provides type-safe SID parsing via
//! [`TryFrom<u8>`] so the dispatcher never compares raw bytes directly:
//!
//! ```rust
//! use uds::uds_service_ids::{self, UdsSid};
//! assert_eq!(uds_service_ids::READ_DATA_BY_IDENTIFIER, 0x22);
//! let sid = UdsSid::try_from(0x22).unwrap();
//! assert_eq!(sid, UdsSid::ReadDataByIdentifier);
//! assert_eq!(u8::from(sid), 0x22);
//! ```

/// Session Control (SID 0x10).
pub const SESSION_CONTROL: u8 = 0x10;
/// ECU Reset (SID 0x11).
pub const ECU_RESET: u8 = 0x11;
/// Clear Diagnostic Information (SID 0x14).
pub const CLEAR_DIAGNOSTIC_INFORMATION: u8 = 0x14;
/// Read DTC Information (SID 0x19).
pub const READ_DTC_INFORMATION: u8 = 0x19;
/// Read Data By Identifier (SID 0x22).
pub const READ_DATA_BY_IDENTIFIER: u8 = 0x22;
/// Security Access (SID 0x27).
pub const SECURITY_ACCESS: u8 = 0x27;
/// Communication Control (SID 0x28).
pub const COMMUNICATION_CONTROL: u8 = 0x28;
/// Authentication (SID 0x29).
pub const AUTHENTICATION: u8 = 0x29;
/// Write Data By Identifier (SID 0x2E).
pub const WRITE_DATA_BY_IDENTIFIER: u8 = 0x2E;
/// Input/Output Control By Identifier (SID 0x2F).
pub const INPUT_OUTPUT_CONTROL_BY_IDENTIFIER: u8 = 0x2F;
/// Routine Control (SID 0x31).
pub const ROUTINE_CONTROL: u8 = 0x31;
/// Request Download (SID 0x34).
pub const REQUEST_DOWNLOAD: u8 = 0x34;
/// Transfer Data (SID 0x36).
pub const TRANSFER_DATA: u8 = 0x36;
/// Request Transfer Exit (SID 0x37).
pub const REQUEST_TRANSFER_EXIT: u8 = 0x37;
/// Tester Present (SID 0x3E).
pub const TESTER_PRESENT: u8 = 0x3E;
/// Control DTC Setting (SID 0x85).
pub const CONTROL_DTC_SETTING: u8 = 0x85;
/// Negative Response SID (0x7F) — always the first byte of a negative response frame.
pub const NEGATIVE_RESPONSE: u8 = 0x7F;
/// Bitmask applied to a request SID to produce the positive-response SID (ISO 14229-1 #8.3).
///
/// Example: `READ_DATA_BY_IDENTIFIER | POSITIVE_RESPONSE_BITMASK == 0x62`.
pub const POSITIVE_RESPONSE_BITMASK: u8 = 0x40;

// ── UdsSid ────────────────────────────────────────────────────────────────────

/// Typed UDS Service Identifier (ISO 14229-1).
///
/// All services defined in the specification are listed here.  The enum is
/// `#[non_exhaustive]` so that new SIDs can be added without breaking existing
/// exhaustive `match` arms in downstream crates.
///
/// # Conversion
///
/// Convert to/from `u8` with [`TryFrom<u8>`] / [`From<UdsSid>`]:
///
/// ```rust
/// use uds::uds_service_ids::UdsSid;
/// assert_eq!(UdsSid::try_from(0x22), Ok(UdsSid::ReadDataByIdentifier));
/// assert_eq!(UdsSid::try_from(0xFF), Err(0xFF));
/// assert_eq!(u8::from(UdsSid::WriteDataByIdentifier), 0x2E);
/// ```
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum UdsSid {
    /// Diagnostic Session Control (0x10).
    DiagnosticSessionControl,
    /// ECU Reset (0x11).
    EcuReset,
    /// Clear Diagnostic Information (0x14).
    ClearDiagnosticInformation,
    /// Read DTC Information (0x19).
    ReadDtcInformation,
    /// Read Data By Identifier (0x22).
    ReadDataByIdentifier,
    /// Security Access (0x27).
    SecurityAccess,
    /// Communication Control (0x28).
    CommunicationControl,
    /// Authentication (0x29).
    Authentication,
    /// Write Data By Identifier (0x2E).
    WriteDataByIdentifier,
    /// Input/Output Control By Identifier (0x2F).
    InputOutputControlByIdentifier,
    /// Routine Control (0x31).
    RoutineControl,
    /// Request Download (0x34).
    RequestDownload,
    /// Transfer Data (0x36).
    TransferData,
    /// Request Transfer Exit (0x37).
    RequestTransferExit,
    /// Tester Present (0x3E).
    TesterPresent,
    /// Control DTC Setting (0x85).
    ControlDtcSetting,
}

impl TryFrom<u8> for UdsSid {
    /// The unrecognised byte is returned on error so callers can log or
    /// encode an NRC without re-reading the original buffer.
    type Error = u8;

    fn try_from(sid: u8) -> Result<Self, Self::Error> {
        match sid {
            SESSION_CONTROL => Ok(Self::DiagnosticSessionControl),
            ECU_RESET => Ok(Self::EcuReset),
            CLEAR_DIAGNOSTIC_INFORMATION => Ok(Self::ClearDiagnosticInformation),
            READ_DTC_INFORMATION => Ok(Self::ReadDtcInformation),
            READ_DATA_BY_IDENTIFIER => Ok(Self::ReadDataByIdentifier),
            SECURITY_ACCESS => Ok(Self::SecurityAccess),
            COMMUNICATION_CONTROL => Ok(Self::CommunicationControl),
            AUTHENTICATION => Ok(Self::Authentication),
            WRITE_DATA_BY_IDENTIFIER => Ok(Self::WriteDataByIdentifier),
            INPUT_OUTPUT_CONTROL_BY_IDENTIFIER => Ok(Self::InputOutputControlByIdentifier),
            ROUTINE_CONTROL => Ok(Self::RoutineControl),
            REQUEST_DOWNLOAD => Ok(Self::RequestDownload),
            TRANSFER_DATA => Ok(Self::TransferData),
            REQUEST_TRANSFER_EXIT => Ok(Self::RequestTransferExit),
            TESTER_PRESENT => Ok(Self::TesterPresent),
            CONTROL_DTC_SETTING => Ok(Self::ControlDtcSetting),
            unknown => Err(unknown),
        }
    }
}

impl From<UdsSid> for u8 {
    fn from(sid: UdsSid) -> Self {
        match sid {
            UdsSid::DiagnosticSessionControl => SESSION_CONTROL,
            UdsSid::EcuReset => ECU_RESET,
            UdsSid::ClearDiagnosticInformation => CLEAR_DIAGNOSTIC_INFORMATION,
            UdsSid::ReadDtcInformation => READ_DTC_INFORMATION,
            UdsSid::ReadDataByIdentifier => READ_DATA_BY_IDENTIFIER,
            UdsSid::SecurityAccess => SECURITY_ACCESS,
            UdsSid::CommunicationControl => COMMUNICATION_CONTROL,
            UdsSid::Authentication => AUTHENTICATION,
            UdsSid::WriteDataByIdentifier => WRITE_DATA_BY_IDENTIFIER,
            UdsSid::InputOutputControlByIdentifier => INPUT_OUTPUT_CONTROL_BY_IDENTIFIER,
            UdsSid::RoutineControl => ROUTINE_CONTROL,
            UdsSid::RequestDownload => REQUEST_DOWNLOAD,
            UdsSid::TransferData => TRANSFER_DATA,
            UdsSid::RequestTransferExit => REQUEST_TRANSFER_EXIT,
            UdsSid::TesterPresent => TESTER_PRESENT,
            UdsSid::ControlDtcSetting => CONTROL_DTC_SETTING,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn known_sids_round_trip() {
        let cases: &[(u8, UdsSid)] = &[
            (0x10, UdsSid::DiagnosticSessionControl),
            (0x11, UdsSid::EcuReset),
            (0x14, UdsSid::ClearDiagnosticInformation),
            (0x19, UdsSid::ReadDtcInformation),
            (0x22, UdsSid::ReadDataByIdentifier),
            (0x27, UdsSid::SecurityAccess),
            (0x28, UdsSid::CommunicationControl),
            (0x29, UdsSid::Authentication),
            (0x2E, UdsSid::WriteDataByIdentifier),
            (0x2F, UdsSid::InputOutputControlByIdentifier),
            (0x31, UdsSid::RoutineControl),
            (0x34, UdsSid::RequestDownload),
            (0x36, UdsSid::TransferData),
            (0x37, UdsSid::RequestTransferExit),
            (0x3E, UdsSid::TesterPresent),
            (0x85, UdsSid::ControlDtcSetting),
        ];
        for &(byte, variant) in cases {
            assert_eq!(UdsSid::try_from(byte), Ok(variant), "try_from(0x{byte:02X}) failed");
            assert_eq!(u8::from(variant), byte, "From<UdsSid> for 0x{byte:02X} failed");
        }
    }

    #[test]
    fn all_known_sids_covered_by_round_trip() {
        // Every constant in this module must have a matching UdsSid variant.
        let constants: &[u8] = &[
            SESSION_CONTROL,
            ECU_RESET,
            CLEAR_DIAGNOSTIC_INFORMATION,
            READ_DTC_INFORMATION,
            READ_DATA_BY_IDENTIFIER,
            SECURITY_ACCESS,
            COMMUNICATION_CONTROL,
            AUTHENTICATION,
            WRITE_DATA_BY_IDENTIFIER,
            INPUT_OUTPUT_CONTROL_BY_IDENTIFIER,
            ROUTINE_CONTROL,
            REQUEST_DOWNLOAD,
            TRANSFER_DATA,
            REQUEST_TRANSFER_EXIT,
            TESTER_PRESENT,
            CONTROL_DTC_SETTING,
        ];
        for &c in constants {
            assert!(
                UdsSid::try_from(c).is_ok(),
                "Constant 0x{c:02X} has no UdsSid variant — add one"
            );
        }
    }

    #[test]
    fn unknown_sid_returns_err_with_byte() {
        assert_eq!(UdsSid::try_from(0xFF), Err(0xFF));
        assert_eq!(UdsSid::try_from(0x00), Err(0x00));
        // Response SID bitmask is not a request SID
        assert_eq!(UdsSid::try_from(0x40), Err(0x40));
        // Negative response SID is not a request SID
        assert_eq!(UdsSid::try_from(NEGATIVE_RESPONSE), Err(NEGATIVE_RESPONSE));
    }

    #[test]
    fn positive_response_bitmask_produces_expected_sids() {
        assert_eq!(
            READ_DATA_BY_IDENTIFIER | POSITIVE_RESPONSE_BITMASK,
            0x62,
            "RDBI positive response SID"
        );
        assert_eq!(
            WRITE_DATA_BY_IDENTIFIER | POSITIVE_RESPONSE_BITMASK,
            0x6E,
            "WDBI positive response SID"
        );
    }

    #[test]
    fn uds_sid_debug_format_contains_variant_name() {
        let s = format!("{:?}", UdsSid::ReadDataByIdentifier);
        assert!(s.contains("ReadDataByIdentifier"));
    }

    #[test]
    fn uds_sid_clone_copy_semantics() {
        let a = UdsSid::TesterPresent;
        let b = a; // Copy
        assert_eq!(a, b);
        let c = a; // Copy — same as clone for Copy types
        assert_eq!(a, c);
    }
}
