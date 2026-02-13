use crate::AppState;
use crate::error::AppError;

use super::hash::hash_api_key;

/// Axum extractor for admin auth. Checks the Bearer token against:
/// 1. The `admins` table (hashed key lookup)
/// 2. Falls back to `ADMIN_SECRET` env var for bootstrap
pub struct AdminAuth;

impl axum::extract::FromRequestParts<AppState> for AdminAuth {
    type Rejection = AppError;

    async fn from_request_parts(
        parts: &mut axum::http::request::Parts,
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

        // Check admins table first
        let key_hash = hash_api_key(token);
        let found: Option<(String,)> =
            sqlx::query_as("SELECT id::text FROM admins WHERE api_key_hash = $1")
                .bind(&key_hash)
                .fetch_optional(&state.db)
                .await
                .map_err(|e| AppError::Internal(format!("admin auth query failed: {e}")))?;

        if let Some((admin_id,)) = found {
            // Update last_used_at in the background
            let db = state.db.clone();
            let admin_id = admin_id.clone();
            tokio::spawn(async move {
                let _ = sqlx::query("UPDATE admins SET last_used_at = NOW() WHERE id::text = $1")
                    .bind(&admin_id)
                    .execute(&db)
                    .await;
            });
            return Ok(AdminAuth);
        }

        // Fall back to ADMIN_SECRET env var
        if let Some(ref secret) = state.config.admin_secret
            && token == secret
        {
            return Ok(AdminAuth);
        }

        Err(AppError::Auth("invalid admin credentials".into()))
    }
}
