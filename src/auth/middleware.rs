use axum::extract::FromRequestParts;
use axum::http::request::Parts;
use axum_extra::extract::cookie::{Key, SignedCookieJar};

use crate::AppState;
use crate::auth::COOKIE_NAME;
use crate::error::AppError;

/// Authenticated user identity.
///
/// Tries two auth paths in order:
/// 1. Signed cookie (web UI sessions via OAuth)
/// 2. Bearer token starting with `hv_` (API key — handled downstream by UserAuth)
/// 3. Bearer service auth JWT (AT Protocol inter-service calls)
#[derive(Debug, Clone)]
pub struct Claims {
    did: String,
}

impl Claims {
    /// The authenticated user's DID.
    pub fn did(&self) -> &str {
        &self.did
    }

    /// Test-only constructor.
    #[cfg(test)]
    pub fn new_for_test(did: String) -> Self {
        Self { did }
    }
}

impl FromRequestParts<AppState> for Claims {
    type Rejection = AppError;

    async fn from_request_parts(
        parts: &mut Parts,
        state: &AppState,
    ) -> Result<Self, Self::Rejection> {
        // Path 1: Cookie auth (web UI)
        let jar: SignedCookieJar<Key> = SignedCookieJar::from_request_parts(parts, state)
            .await
            .map_err(|_| AppError::Auth("failed to read cookies".into()))?;

        if let Some(cookie) = jar.get(COOKIE_NAME) {
            let did = cookie.value().to_string();
            return Ok(Claims { did });
        }

        // Path 2: Authorization header
        let header = parts
            .headers
            .get("authorization")
            .and_then(|v| v.to_str().ok())
            .ok_or_else(|| {
                AppError::Auth("missing Authorization header or session cookie".into())
            })?;

        if let Some(token) = header.strip_prefix("Bearer ") {
            // API key tokens start with hv_ — let them through with a placeholder DID.
            // The admin middleware (UserAuth) will resolve the actual DID from the API key.
            if token.starts_with("hv_") {
                // API key auth is handled by UserAuth extractor which looks up the key.
                // We need to extract the DID from the api_keys table.
                let did = resolve_api_key_did(state, token).await?;
                return Ok(Claims { did });
            }

            // Otherwise, try service auth JWT
            let service_auth = super::service_auth::ServiceAuth::from_bearer(token, state).await?;
            return Ok(Claims {
                did: service_auth.did,
            });
        }

        Err(AppError::Auth("invalid Authorization scheme".into()))
    }
}

/// Look up the DID associated with an API key.
async fn resolve_api_key_did(state: &AppState, token: &str) -> Result<String, AppError> {
    use crate::db::adapt_sql;
    use sha2::{Digest, Sha256};

    let hash = hex::encode(Sha256::digest(token.as_bytes()));
    let sql = adapt_sql(
        "SELECT u.did FROM api_keys k JOIN users u ON k.user_id = u.id WHERE k.key_hash = ? AND k.revoked_at IS NULL",
        state.db_backend,
    );
    let row: Option<(String,)> = sqlx::query_as(&sql)
        .bind(&hash)
        .fetch_optional(&state.db)
        .await
        .map_err(|e| AppError::Internal(format!("API key lookup failed: {e}")))?;

    row.map(|(did,)| did)
        .ok_or_else(|| AppError::Auth("invalid API key".into()))
}
