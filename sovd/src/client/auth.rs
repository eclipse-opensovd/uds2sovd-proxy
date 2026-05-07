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

//! `OAuth2` client-credentials wire types for the SOVD gateway.
//!
//! Separated from [`super`] so the HTTP request/response structs and the token
//! cache logic are not mixed with the gateway `read`/`write` operations.

use serde::{Deserialize, Serialize};

// ── Wire types ────────────────────────────────────────────────────────────────

/// `OAuth2` token request body (client-credentials grant).
#[derive(Serialize)]
pub(super) struct AuthRequest {
    pub(super) client_id: String,
    pub(super) client_secret: String,
}

/// `OAuth2` token response body.
#[derive(Deserialize)]
pub(super) struct AuthResponse {
    pub(super) access_token: String,
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn auth_request_serializes_client_credentials() {
        let req =
            AuthRequest { client_id: "my-client".to_string(), client_secret: "secret".to_string() };
        let json = serde_json::to_string(&req).expect("must serialize");
        assert!(json.contains("my-client") && json.contains("secret"));
    }

    #[test]
    fn auth_response_deserializes_token() {
        let json =
            r#"{"access_token":"eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9","expires_in":3600}"#;
        let resp: AuthResponse = serde_json::from_str(json).expect("must deserialize");
        assert!(resp.access_token.starts_with("eyJ"));
    }
}
