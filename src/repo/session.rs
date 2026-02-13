use serde::Deserialize;

use crate::AppState;
use crate::error::AppError;

#[derive(Deserialize)]
pub(crate) struct AtpSession {
    pub(crate) access_token: String,
    pub(crate) pds_endpoint: String,
    pub(crate) dpop_jwk: DpopJwk,
}

#[derive(Deserialize)]
pub(crate) struct DpopJwk {
    pub(crate) x: String,
    pub(crate) y: String,
    pub(crate) d: String,
}

/// Fetch the user's AT Protocol session (PDS credentials) from AIP.
pub(crate) async fn get_atp_session(state: &AppState, token: &str) -> Result<AtpSession, AppError> {
    let url = format!(
        "{}/api/atprotocol/session",
        state.config.aip_url.trim_end_matches('/')
    );

    let resp = state
        .http
        .get(&url)
        .header("authorization", format!("Bearer {token}"))
        .send()
        .await
        .map_err(|e| AppError::Internal(format!("AIP session request failed: {e}")))?;

    if !resp.status().is_success() {
        return Err(AppError::Auth(format!(
            "AIP session returned {}",
            resp.status()
        )));
    }

    resp.json()
        .await
        .map_err(|e| AppError::Internal(format!("invalid AIP session response: {e}")))
}
