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

/// Test-only [`SovdProxy`] implementation that echoes the request bytes.
pub struct MockProxy;

impl SovdProxy for MockProxy {
    fn process(&self, uds_request: &[u8]) -> Result<Vec<u8>, SovdProxyError> {
        Ok(uds_request.to_vec())
    }
}
