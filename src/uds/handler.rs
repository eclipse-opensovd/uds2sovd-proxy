//! UDS Handler Trait
//!
//! Defines the interface between DoIP transport and UDS processing.
//! The DoIP server extracts UDS bytes from DoIP frames and delegates
//! to the handler. The handler returns UDS response bytes.

use bytes::Bytes;

/// UDS request extracted from DoIP diagnostic message
#[derive(Debug, Clone)]
pub struct UdsRequest {
    pub source_address: u16,
    pub target_address: u16,
    pub data: Bytes,
}

impl UdsRequest {
    pub fn new(source: u16, target: u16, data: Bytes) -> Self {
        Self {
            source_address: source,
            target_address: target,
            data,
        }
    }

    pub fn service_id(&self) -> Option<u8> {
        self.data.first().copied()
    }
}

/// UDS response to be wrapped in DoIP diagnostic message
#[derive(Debug, Clone)]
pub struct UdsResponse {
    pub source_address: u16,
    pub target_address: u16,
    pub data: Bytes,
}

impl UdsResponse {
    pub fn new(source: u16, target: u16, data: Bytes) -> Self {
        Self {
            source_address: source,
            target_address: target,
            data,
        }
    }
}

/// Trait for handling UDS requests
///
/// Implement this trait to connect the DoIP server to a UDS backend
/// (e.g., UDS2SOVD converter, ODX/MDD handler, or ECU simulator)
pub trait UdsHandler: Send + Sync {
    fn handle(&self, request: UdsRequest) -> UdsResponse;
}

/// Stub handler that returns NRC 0x11 (Service Not Supported) for all requests
#[derive(Debug, Default, Clone)]
pub struct StubHandler;

impl UdsHandler for StubHandler {
    fn handle(&self, request: UdsRequest) -> UdsResponse {
        let sid = request.service_id().unwrap_or(0);
        // Negative response: 0x7F + SID + NRC
        let nrc_service_not_supported = 0x11;
        let data = Bytes::from(vec![0x7F, sid, nrc_service_not_supported]);

        UdsResponse::new(
            request.target_address,
            request.source_address,
            data,
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn stub_handler_returns_nrc() {
        let handler = StubHandler;
        let request = UdsRequest::new(
            0x0E00,
            0x1000,
            Bytes::from(vec![0x22, 0xF1, 0x90]), // ReadDataByIdentifier
        );

        let response = handler.handle(request);

        assert_eq!(response.source_address, 0x1000);
        assert_eq!(response.target_address, 0x0E00);
        assert_eq!(response.data.as_ref(), &[0x7F, 0x22, 0x11]);
    }

    #[test]
    fn stub_handler_handles_empty_request() {
        let handler = StubHandler;
        let request = UdsRequest::new(0x0E00, 0x1000, Bytes::new());

        let response = handler.handle(request);

        assert_eq!(response.data.as_ref(), &[0x7F, 0x00, 0x11]);
    }

    #[test]
    fn stub_handler_tester_present() {
        let handler = StubHandler;
        let request = UdsRequest::new(
            0x0E00,
            0x1000,
            Bytes::from(vec![0x3E, 0x00]), // TesterPresent
        );

        let response = handler.handle(request);

        assert_eq!(response.data.as_ref(), &[0x7F, 0x3E, 0x11]);
    }

    #[test]
    fn uds_request_service_id() {
        let request = UdsRequest::new(0x0E00, 0x1000, Bytes::from(vec![0x10, 0x01]));
        assert_eq!(request.service_id(), Some(0x10));

        let empty = UdsRequest::new(0x0E00, 0x1000, Bytes::new());
        assert_eq!(empty.service_id(), None);
    }
}
