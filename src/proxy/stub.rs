// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 The Contributors to Eclipse OpenSOVD (see CONTRIBUTORS)
//
// See the NOTICE file(s) distributed with this work for additional
// information regarding copyright ownership.
//
// This program and the accompanying materials are made available under the
// terms of the Apache License Version 2.0 which is available at
// https://www.apache.org/licenses/LICENSE-2.0

use super::{SovdProxy, SovdProxyError};

/// [`SovdProxy`] implementation that returns UDS NRC `0x11` for every request.
pub struct StubProxy;

impl SovdProxy for StubProxy {
    fn process(&self, uds_request: &[u8]) -> Result<Vec<u8>, SovdProxyError> {
        if uds_request.is_empty() {
            return Err(SovdProxyError::InvalidResponse);
        }
        // UDS Negative Response: 0x7F <service_id> 0x11 (serviceNotSupported)
        Ok(vec![0x7F, uds_request[0], 0x11])
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn stub_returns_nrc_service_not_supported() {
        let proxy = StubProxy;
        let resp = proxy.process(&[0x22, 0xF1, 0x90]).unwrap();
        assert_eq!(resp, vec![0x7F, 0x22, 0x11]);
    }

    #[test]
    fn stub_errors_on_empty_request() {
        let proxy = StubProxy;
        assert!(proxy.process(&[]).is_err());
    }
}
