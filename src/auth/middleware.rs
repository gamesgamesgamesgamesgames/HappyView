use axum::extract::FromRequestParts;
use axum::http::request::Parts;
use serde::Deserialize;

use crate::AppState;
use crate::error::AppError;

/// Authenticated user identity extracted from an AIP-issued access token.
#[derive(Debug, Clone)]
pub struct Claims {
    did: String,
    token: String,
    dpop_proof: Option<String>,
}

impl Claims {
    /// The authenticated user's DID.
    pub fn did(&self) -> &str {
        &self.did
    }

    /// The raw access token for forwarding to AIP's XRPC proxy.
    pub fn token(&self) -> &str {
        &self.token
    }

    /// The DPoP proof from the client request, if present.
    pub fn dpop_proof(&self) -> Option<&str> {
        self.dpop_proof.as_deref()
    }

    /// Test-only constructor.
    #[cfg(test)]
    pub fn new_for_test(did: String, token: String) -> Self {
        Self {
            did,
            token,
            dpop_proof: None,
        }
    }
}

#[derive(Deserialize)]
struct UserinfoResponse {
    sub: String,
}

/// Axum extractor that validates the Bearer token by forwarding it to AIP's
/// `/oauth/userinfo` endpoint. AIP returns the DID in the `sub` field.
impl FromRequestParts<AppState> for Claims {
    type Rejection = AppError;

    async fn from_request_parts(
        parts: &mut Parts,
        state: &AppState,
    ) -> Result<Self, Self::Rejection> {
        let header = parts
            .headers
            .get("authorization")
            .and_then(|v| v.to_str().ok())
            .ok_or_else(|| AppError::Auth("missing Authorization header".into()))?;

        let token = header
            .strip_prefix("DPoP ")
            .or_else(|| header.strip_prefix("Bearer "))
            .ok_or_else(|| AppError::Auth("invalid Authorization scheme".into()))?;

        let dpop_proof = parts
            .headers
            .get("dpop")
            .and_then(|v| v.to_str().ok())
            .map(|s| s.to_string());

        let userinfo_url = format!(
            "{}/oauth/userinfo",
            state.config.aip_url.trim_end_matches('/')
        );

        tracing::debug!(
            url = %userinfo_url,
            has_dpop_proof = dpop_proof.is_some(),
            "forwarding token to AIP userinfo"
        );

        let mut req = state
            .http
            .get(&userinfo_url)
            .header("authorization", format!("DPoP {token}"));

        if let Some(ref proof) = dpop_proof {
            req = req.header("dpop", proof);
        }

        let resp = req.send().await.map_err(|e| {
            tracing::error!(url = %userinfo_url, error = %e, "AIP userinfo request failed to send");
            AppError::Auth(format!("userinfo request failed: {e}"))
        })?;

        if !resp.status().is_success() {
            let status = resp.status();
            let nonce = resp
                .headers()
                .get("dpop-nonce")
                .and_then(|v| v.to_str().ok())
                .map(String::from);
            let body = resp.text().await.unwrap_or_default();

            tracing::warn!(
                url = %userinfo_url,
                status = %status,
                body = %body,
                dpop_nonce = ?nonce,
                has_dpop_proof = dpop_proof.is_some(),
                "AIP userinfo request failed"
            );

            // Relay the nonce so the client can retry with it.
            if let Some(ref nonce_str) = nonce {
                return Err(AppError::AuthDpopNonce(nonce_str.clone()));
            }

            return Err(AppError::Auth(format!(
                "userinfo returned {}: {}",
                status, body
            )));
        }

        let info: UserinfoResponse = resp
            .json()
            .await
            .map_err(|e| AppError::Auth(format!("invalid userinfo response: {e}")))?;

        Ok(Claims {
            did: info.sub,
            token: token.to_string(),
            dpop_proof,
        })
    }
}
