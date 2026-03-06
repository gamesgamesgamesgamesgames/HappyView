use axum::extract::FromRequestParts;
use axum::http::request::Parts;
use sha2::{Digest, Sha256};

use crate::AppState;
use crate::auth::middleware::Claims;
use crate::error::AppError;
use crate::event_log::{EventLog, Severity, log_event};

/// Axum extractor for admin auth. Validates the Bearer token via AIP OAuth
/// (same as `Claims`), then checks if the returned DID exists in the `admins`
/// table. If no admins exist yet, the first authenticated user is
/// auto-bootstrapped as the initial admin.
///
/// Also supports `hv_`-prefixed API keys: the token is SHA-256 hashed and
/// looked up in `admin_api_keys`. If found, the admin's DID is returned.
pub struct AdminAuth {
    pub did: String,
}

impl FromRequestParts<AppState> for AdminAuth {
    type Rejection = AppError;

    async fn from_request_parts(
        parts: &mut Parts,
        state: &AppState,
    ) -> Result<Self, Self::Rejection> {
        // Check for API key auth first (Bearer hv_...).
        if let Some(auth) = Self::try_api_key_auth(parts, state).await? {
            return Ok(auth);
        }

        // Validate the Bearer token via AIP userinfo (reuse Claims extractor).
        let claims = Claims::from_request_parts(parts, state).await?;
        let did = claims.did().to_string();

        // Check whether the admins table is empty (auto-bootstrap case).
        let count: (i64,) = sqlx::query_as("SELECT COUNT(*) FROM admins")
            .fetch_one(&state.db)
            .await
            .map_err(|e| AppError::Internal(format!("admin count query failed: {e}")))?;

        if count.0 == 0 {
            // First authenticated user becomes the initial admin.
            sqlx::query("INSERT INTO admins (did) VALUES ($1) ON CONFLICT DO NOTHING")
                .bind(&did)
                .execute(&state.db)
                .await
                .map_err(|e| AppError::Internal(format!("auto-bootstrap admin failed: {e}")))?;

            tracing::info!(did = %did, "auto-bootstrapped first admin");

            log_event(
                &state.db,
                EventLog {
                    event_type: "admin.bootstrapped".to_string(),
                    severity: Severity::Info,
                    actor_did: None,
                    subject: Some(did.clone()),
                    detail: serde_json::json!({}),
                },
            )
            .await;
        }

        // Look up the DID in the admins table.
        let found: Option<(String,)> = sqlx::query_as("SELECT id::text FROM admins WHERE did = $1")
            .bind(&did)
            .fetch_optional(&state.db)
            .await
            .map_err(|e| AppError::Internal(format!("admin auth query failed: {e}")))?;

        let Some((admin_id,)) = found else {
            return Err(AppError::Forbidden("not an admin".into()));
        };

        // Update last_used_at in the background.
        let db = state.db.clone();
        tokio::spawn(async move {
            let _ = sqlx::query("UPDATE admins SET last_used_at = NOW() WHERE id::text = $1")
                .bind(&admin_id)
                .execute(&db)
                .await;
        });

        Ok(AdminAuth { did })
    }
}

impl AdminAuth {
    /// If the Authorization header contains a `hv_`-prefixed API key, validate
    /// it against the `admin_api_keys` table and return the owning admin's DID.
    /// Returns `Ok(None)` if the token doesn't start with `hv_`, allowing
    /// fallthrough to the normal OAuth flow.
    async fn try_api_key_auth(parts: &Parts, state: &AppState) -> Result<Option<Self>, AppError> {
        let header = match parts
            .headers
            .get("authorization")
            .and_then(|v| v.to_str().ok())
        {
            Some(h) => h,
            None => return Ok(None),
        };

        let token = header
            .strip_prefix("Bearer ")
            .or_else(|| header.strip_prefix("DPoP "));

        let token = match token {
            Some(t) if t.starts_with("hv_") => t,
            _ => return Ok(None),
        };

        let hash = hex::encode(Sha256::digest(token.as_bytes()));

        let row: Option<(String, String)> = sqlx::query_as(
            "SELECT k.id::text, a.did
             FROM admin_api_keys k
             JOIN admins a ON a.id = k.admin_id
             WHERE k.key_hash = $1 AND k.revoked_at IS NULL",
        )
        .bind(&hash)
        .fetch_optional(&state.db)
        .await
        .map_err(|e| AppError::Internal(format!("api key lookup failed: {e}")))?;

        let Some((key_id, did)) = row else {
            return Err(AppError::Auth("invalid or revoked API key".into()));
        };

        // Update last_used_at in the background.
        let db = state.db.clone();
        tokio::spawn(async move {
            let _ =
                sqlx::query("UPDATE admin_api_keys SET last_used_at = NOW() WHERE id::text = $1")
                    .bind(&key_id)
                    .execute(&db)
                    .await;
        });

        Ok(Some(AdminAuth { did }))
    }
}
