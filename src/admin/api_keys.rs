use axum::Json;
use axum::extract::{Path, State};
use axum::http::StatusCode;
use hex;
use rand::Rng;
use sha2::{Digest, Sha256};

use crate::AppState;
use crate::error::AppError;
use crate::event_log::{EventLog, Severity, log_event};

use super::auth::AdminAuth;
use super::types::{ApiKeySummary, CreateApiKeyBody, CreateApiKeyResponse};

/// POST /admin/api-keys — create a new API key for the authenticated admin.
pub(super) async fn create_api_key(
    State(state): State<AppState>,
    auth: AdminAuth,
    Json(body): Json<CreateApiKeyBody>,
) -> Result<(StatusCode, Json<CreateApiKeyResponse>), AppError> {
    // Look up the admin's UUID from their DID.
    let admin_row: (String,) = sqlx::query_as("SELECT id::text FROM admins WHERE did = $1")
        .bind(&auth.did)
        .fetch_one(&state.db)
        .await
        .map_err(|e| AppError::Internal(format!("failed to find admin: {e}")))?;
    let admin_id = admin_row.0;

    // Generate the raw key: "hv_" + 32 random hex chars.
    let mut random_bytes = [0u8; 16];
    rand::rng().fill(&mut random_bytes);
    let raw_key = format!("hv_{}", hex::encode(random_bytes));

    // SHA-256 hash for storage.
    let hash = hex::encode(Sha256::digest(raw_key.as_bytes()));

    // First 8 chars for display (e.g., "hv_a1b2c3d4").
    let key_prefix = raw_key[..11].to_string(); // "hv_" + 8 hex chars

    let row: (String,) = sqlx::query_as(
        "INSERT INTO admin_api_keys (admin_id, name, key_hash, key_prefix)
         VALUES ($1::uuid, $2, $3, $4)
         RETURNING id::text",
    )
    .bind(&admin_id)
    .bind(&body.name)
    .bind(&hash)
    .bind(&key_prefix)
    .fetch_one(&state.db)
    .await
    .map_err(|e| AppError::Internal(format!("failed to create api key: {e}")))?;

    log_event(
        &state.db,
        EventLog {
            event_type: "api_key.created".to_string(),
            severity: Severity::Info,
            actor_did: Some(auth.did.clone()),
            subject: Some(body.name.clone()),
            detail: serde_json::json!({ "key_prefix": key_prefix }),
        },
    )
    .await;

    Ok((
        StatusCode::CREATED,
        Json(CreateApiKeyResponse {
            id: row.0,
            name: body.name,
            key: raw_key,
            key_prefix,
        }),
    ))
}

/// GET /admin/api-keys — list API keys for the authenticated admin.
pub(super) async fn list_api_keys(
    State(state): State<AppState>,
    auth: AdminAuth,
) -> Result<Json<Vec<ApiKeySummary>>, AppError> {
    #[allow(clippy::type_complexity)]
    let rows: Vec<(
        String,
        String,
        String,
        chrono::DateTime<chrono::Utc>,
        Option<chrono::DateTime<chrono::Utc>>,
        Option<chrono::DateTime<chrono::Utc>>,
    )> = sqlx::query_as(
        "SELECT k.id::text, k.name, k.key_prefix, k.created_at, k.last_used_at, k.revoked_at
         FROM admin_api_keys k
         JOIN admins a ON a.id = k.admin_id
         WHERE a.did = $1
         ORDER BY k.created_at DESC",
    )
    .bind(&auth.did)
    .fetch_all(&state.db)
    .await
    .map_err(|e| AppError::Internal(format!("failed to list api keys: {e}")))?;

    let keys: Vec<ApiKeySummary> = rows
        .into_iter()
        .map(
            |(id, name, key_prefix, created_at, last_used_at, revoked_at)| ApiKeySummary {
                id,
                name,
                key_prefix,
                created_at,
                last_used_at,
                revoked_at,
            },
        )
        .collect();

    Ok(Json(keys))
}

/// DELETE /admin/api-keys/:id — revoke an API key (soft delete).
pub(super) async fn revoke_api_key(
    State(state): State<AppState>,
    auth: AdminAuth,
    Path(id): Path<String>,
) -> Result<StatusCode, AppError> {
    let result = sqlx::query(
        "UPDATE admin_api_keys SET revoked_at = NOW()
         WHERE id::text = $1
           AND admin_id = (SELECT id FROM admins WHERE did = $2)
           AND revoked_at IS NULL",
    )
    .bind(&id)
    .bind(&auth.did)
    .execute(&state.db)
    .await
    .map_err(|e| AppError::Internal(format!("failed to revoke api key: {e}")))?;

    if result.rows_affected() == 0 {
        return Err(AppError::NotFound(format!("api key '{id}' not found")));
    }

    log_event(
        &state.db,
        EventLog {
            event_type: "api_key.revoked".to_string(),
            severity: Severity::Info,
            actor_did: Some(auth.did.clone()),
            subject: Some(id.to_string()),
            detail: serde_json::json!({}),
        },
    )
    .await;

    Ok(StatusCode::NO_CONTENT)
}
