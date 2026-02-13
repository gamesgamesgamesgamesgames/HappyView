use axum::extract::FromRequestParts;
use axum::http::request::Parts;

use crate::AppState;
use crate::auth::middleware::Claims;
use crate::error::AppError;

/// Axum extractor for admin auth. Validates the Bearer token via AIP OAuth
/// (same as `Claims`), then checks if the returned DID exists in the `admins`
/// table. If no admins exist yet, the first authenticated user is
/// auto-bootstrapped as the initial admin.
pub struct AdminAuth {
    did: String,
}

impl AdminAuth {
    /// The authenticated admin's DID.
    pub fn did(&self) -> &str {
        &self.did
    }
}

impl FromRequestParts<AppState> for AdminAuth {
    type Rejection = AppError;

    async fn from_request_parts(
        parts: &mut Parts,
        state: &AppState,
    ) -> Result<Self, Self::Rejection> {
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
        }

        // Look up the DID in the admins table.
        let found: Option<(String,)> =
            sqlx::query_as("SELECT id::text FROM admins WHERE did = $1")
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
