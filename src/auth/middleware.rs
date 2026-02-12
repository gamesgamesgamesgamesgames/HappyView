use axum::extract::FromRequestParts;
use axum::http::request::Parts;
use serde::Deserialize;

use crate::error::AppError;
use crate::AppState;

/// Authenticated user identity extracted from an AIP-issued access token.
#[derive(Debug, Clone)]
pub struct Claims {
    did: String,
}

impl Claims {
    /// The authenticated user's DID.
    pub fn did(&self) -> &str {
        &self.did
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
            .strip_prefix("Bearer ")
            .ok_or_else(|| AppError::Auth("invalid Authorization scheme".into()))?;

        let userinfo_url = format!(
            "{}/oauth/userinfo",
            state.config.aip_url.trim_end_matches('/')
        );

        let resp = state
            .http
            .get(&userinfo_url)
            .header("authorization", format!("Bearer {token}"))
            .send()
            .await
            .map_err(|e| AppError::Auth(format!("userinfo request failed: {e}")))?;

        if !resp.status().is_success() {
            return Err(AppError::Auth(format!(
                "userinfo returned {}",
                resp.status()
            )));
        }

        let info: UserinfoResponse = resp
            .json()
            .await
            .map_err(|e| AppError::Auth(format!("invalid userinfo response: {e}")))?;

        Ok(Claims { did: info.sub })
    }
}
