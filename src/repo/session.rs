use atrium_api::types::string::Did;

use crate::AppState;
use crate::HappyViewOAuthSession;
use crate::error::AppError;

/// Resume an OAuth session for the given DID via atrium.
/// The returned `OAuthSession` handles DPoP and token refresh internally.
pub(crate) async fn get_oauth_session(
    state: &AppState,
    did: &str,
) -> Result<HappyViewOAuthSession, AppError> {
    let did =
        Did::new(did.to_string()).map_err(|_| AppError::Auth(format!("invalid DID: {did}")))?;
    state
        .oauth
        .default_client()
        .restore(&did)
        .await
        .map_err(|e| AppError::Auth(format!("no OAuth session for {}: {e}", did.as_ref())))
}
