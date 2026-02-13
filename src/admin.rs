use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::routing::{delete, get, post};
use axum::{Json, Router};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};

use crate::AppState;
use crate::error::AppError;
use crate::lexicon::{LexiconType, ParsedLexicon};

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// SHA-256 hash a plaintext API key for storage/comparison.
pub(crate) fn hash_api_key(key: &str) -> String {
    let hash = Sha256::digest(key.as_bytes());
    hex::encode(hash)
}

// ---------------------------------------------------------------------------
// Admin auth middleware
// ---------------------------------------------------------------------------

pub fn admin_routes(_state: AppState) -> Router<AppState> {
    Router::new()
        .route("/lexicons", post(upload_lexicon).get(list_lexicons))
        .route("/lexicons/{id}", get(get_lexicon).delete(delete_lexicon))
        .route("/stats", get(stats))
        .route("/backfill", post(create_backfill))
        .route("/backfill/status", get(backfill_status))
        .route("/admins", post(create_admin).get(list_admins))
        .route("/admins/{id}", delete(delete_admin))
}

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

/// Bootstrap: if no admins exist and ADMIN_SECRET is set, create a bootstrap admin.
pub async fn bootstrap(db: &sqlx::PgPool, admin_secret: &Option<String>) {
    let count: (i64,) = sqlx::query_as("SELECT COUNT(*) FROM admins")
        .fetch_one(db)
        .await
        .unwrap_or((0,));

    if count.0 > 0 {
        return;
    }

    if let Some(secret) = admin_secret {
        let key_hash = hash_api_key(secret);
        let _ = sqlx::query(
            "INSERT INTO admins (name, api_key_hash) VALUES ($1, $2) ON CONFLICT DO NOTHING",
        )
        .bind("bootstrap")
        .bind(&key_hash)
        .execute(db)
        .await;
        tracing::info!("created bootstrap admin from ADMIN_SECRET");
    }
}

// ---------------------------------------------------------------------------
// Jetstream notification
// ---------------------------------------------------------------------------

/// Send the current record collection list to the Jetstream task so it
/// reconnects with the updated filter.
async fn notify_jetstream(state: &AppState) {
    let collections = state.lexicons.get_record_collections().await;
    let _ = state.collections_tx.send(collections);
}

// ---------------------------------------------------------------------------
// Request / response types
// ---------------------------------------------------------------------------

#[derive(Serialize)]
struct LexiconSummary {
    id: String,
    revision: i32,
    lexicon_type: String,
    backfill: bool,
    created_at: chrono::DateTime<chrono::Utc>,
    updated_at: chrono::DateTime<chrono::Utc>,
}

#[derive(Deserialize)]
struct UploadLexiconBody {
    lexicon_json: Value,
    #[serde(default = "default_backfill")]
    backfill: bool,
    target_collection: Option<String>,
}

fn default_backfill() -> bool {
    true
}

#[derive(Serialize)]
struct StatsResponse {
    total_records: i64,
    collections: Vec<CollectionStat>,
}

#[derive(Serialize)]
struct CollectionStat {
    collection: String,
    count: i64,
}

// ---------------------------------------------------------------------------
// Handlers
// ---------------------------------------------------------------------------

/// POST /admin/lexicons — upload (upsert) a lexicon.
async fn upload_lexicon(
    State(state): State<AppState>,
    _admin: AdminAuth,
    Json(body): Json<UploadLexiconBody>,
) -> Result<(StatusCode, Json<Value>), AppError> {
    // Validate basic structure
    let lexicon_version = body
        .lexicon_json
        .get("lexicon")
        .and_then(|v| v.as_i64())
        .ok_or_else(|| {
            AppError::BadRequest("lexicon JSON must have a numeric 'lexicon' field".into())
        })?;

    if lexicon_version != 1 {
        return Err(AppError::BadRequest(format!(
            "unsupported lexicon version: {lexicon_version}"
        )));
    }

    let id = body
        .lexicon_json
        .get("id")
        .and_then(|v| v.as_str())
        .ok_or_else(|| AppError::BadRequest("lexicon JSON must have a string 'id' field".into()))?
        .to_string();

    // Validate it parses correctly
    ParsedLexicon::parse(body.lexicon_json.clone(), 1, body.target_collection.clone())
        .map_err(|e| AppError::BadRequest(format!("failed to parse lexicon: {e}")))?;

    // Upsert into database
    let row: (i32,) = sqlx::query_as(
        r#"
        INSERT INTO lexicons (id, lexicon_json, backfill, target_collection)
        VALUES ($1, $2, $3, $4)
        ON CONFLICT (id) DO UPDATE SET
            lexicon_json = EXCLUDED.lexicon_json,
            backfill = EXCLUDED.backfill,
            target_collection = EXCLUDED.target_collection,
            revision = lexicons.revision + 1,
            updated_at = NOW()
        RETURNING revision
        "#,
    )
    .bind(&id)
    .bind(&body.lexicon_json)
    .bind(body.backfill)
    .bind(&body.target_collection)
    .fetch_one(&state.db)
    .await
    .map_err(|e| AppError::Internal(format!("failed to upsert lexicon: {e}")))?;

    let revision = row.0;

    // Update in-memory registry with correct revision
    let parsed = ParsedLexicon::parse(body.lexicon_json, revision, body.target_collection)
        .map_err(|e| AppError::Internal(format!("failed to re-parse lexicon: {e}")))?;
    let is_record = parsed.lexicon_type == LexiconType::Record;
    state.lexicons.upsert(parsed).await;

    if is_record {
        notify_jetstream(&state).await;
    }

    let status = if revision == 1 {
        StatusCode::CREATED
    } else {
        StatusCode::OK
    };

    Ok((
        status,
        Json(serde_json::json!({
            "id": id,
            "revision": revision,
        })),
    ))
}

/// GET /admin/lexicons — list all lexicons.
async fn list_lexicons(
    State(state): State<AppState>,
    _admin: AdminAuth,
) -> Result<Json<Vec<LexiconSummary>>, AppError> {
    #[allow(clippy::type_complexity)]
    let rows: Vec<(String, i32, Value, bool, chrono::DateTime<chrono::Utc>, chrono::DateTime<chrono::Utc>)> =
        sqlx::query_as(
            "SELECT id, revision, lexicon_json, backfill, created_at, updated_at FROM lexicons ORDER BY id",
        )
        .fetch_all(&state.db)
        .await
        .map_err(|e| AppError::Internal(format!("failed to list lexicons: {e}")))?;

    let summaries: Vec<LexiconSummary> = rows
        .into_iter()
        .map(|(id, revision, json, backfill, created_at, updated_at)| {
            let lexicon_type = ParsedLexicon::parse(json, revision, None)
                .map(|p| format!("{:?}", p.lexicon_type).to_lowercase())
                .unwrap_or_else(|_| "unknown".into());

            LexiconSummary {
                id,
                revision,
                lexicon_type,
                backfill,
                created_at,
                updated_at,
            }
        })
        .collect();

    Ok(Json(summaries))
}

/// GET /admin/lexicons/:id — get a single lexicon.
async fn get_lexicon(
    State(state): State<AppState>,
    _admin: AdminAuth,
    Path(id): Path<String>,
) -> Result<Json<Value>, AppError> {
    #[allow(clippy::type_complexity)]
    let row: Option<(String, i32, Value, bool, chrono::DateTime<chrono::Utc>, chrono::DateTime<chrono::Utc>)> =
        sqlx::query_as(
            "SELECT id, revision, lexicon_json, backfill, created_at, updated_at FROM lexicons WHERE id = $1",
        )
        .bind(&id)
        .fetch_optional(&state.db)
        .await
        .map_err(|e| AppError::Internal(format!("failed to get lexicon: {e}")))?;

    let (id, revision, lexicon_json, backfill, created_at, updated_at) =
        row.ok_or_else(|| AppError::NotFound(format!("lexicon '{id}' not found")))?;

    Ok(Json(serde_json::json!({
        "id": id,
        "revision": revision,
        "lexicon_json": lexicon_json,
        "backfill": backfill,
        "created_at": created_at,
        "updated_at": updated_at,
    })))
}

/// DELETE /admin/lexicons/:id — remove a lexicon.
async fn delete_lexicon(
    State(state): State<AppState>,
    _admin: AdminAuth,
    Path(id): Path<String>,
) -> Result<StatusCode, AppError> {
    let result = sqlx::query("DELETE FROM lexicons WHERE id = $1")
        .bind(&id)
        .execute(&state.db)
        .await
        .map_err(|e| AppError::Internal(format!("failed to delete lexicon: {e}")))?;

    if result.rows_affected() == 0 {
        return Err(AppError::NotFound(format!("lexicon '{id}' not found")));
    }

    state.lexicons.remove(&id).await;
    notify_jetstream(&state).await;

    Ok(StatusCode::NO_CONTENT)
}

/// GET /admin/stats — system statistics.
async fn stats(
    State(state): State<AppState>,
    _admin: AdminAuth,
) -> Result<Json<StatsResponse>, AppError> {
    let total: (i64,) = sqlx::query_as("SELECT COUNT(*) FROM records")
        .fetch_one(&state.db)
        .await
        .map_err(|e| AppError::Internal(format!("failed to count records: {e}")))?;

    let collections: Vec<(String, i64)> = sqlx::query_as(
        "SELECT collection, COUNT(*) FROM records GROUP BY collection ORDER BY collection",
    )
    .fetch_all(&state.db)
    .await
    .map_err(|e| AppError::Internal(format!("failed to count by collection: {e}")))?;

    Ok(Json(StatsResponse {
        total_records: total.0,
        collections: collections
            .into_iter()
            .map(|(collection, count)| CollectionStat { collection, count })
            .collect(),
    }))
}

// ---------------------------------------------------------------------------
// Backfill endpoints
// ---------------------------------------------------------------------------

#[derive(Deserialize)]
struct CreateBackfillBody {
    collection: Option<String>,
    did: Option<String>,
}

#[derive(Serialize)]
struct BackfillJob {
    id: String,
    collection: Option<String>,
    did: Option<String>,
    status: String,
    total_repos: Option<i32>,
    processed_repos: Option<i32>,
    total_records: Option<i32>,
    error: Option<String>,
    started_at: Option<chrono::DateTime<chrono::Utc>>,
    completed_at: Option<chrono::DateTime<chrono::Utc>>,
    created_at: chrono::DateTime<chrono::Utc>,
}

/// POST /admin/backfill — create a new backfill job.
async fn create_backfill(
    State(state): State<AppState>,
    _admin: AdminAuth,
    Json(body): Json<CreateBackfillBody>,
) -> Result<(StatusCode, Json<Value>), AppError> {
    let row: (String,) = sqlx::query_as(
        "INSERT INTO backfill_jobs (collection, did) VALUES ($1, $2) RETURNING id::text",
    )
    .bind(&body.collection)
    .bind(&body.did)
    .fetch_one(&state.db)
    .await
    .map_err(|e| AppError::Internal(format!("failed to create backfill job: {e}")))?;

    Ok((
        StatusCode::CREATED,
        Json(serde_json::json!({
            "id": row.0,
            "status": "pending",
        })),
    ))
}

/// GET /admin/backfill/status — list all backfill jobs.
async fn backfill_status(
    State(state): State<AppState>,
    _admin: AdminAuth,
) -> Result<Json<Vec<BackfillJob>>, AppError> {
    #[allow(clippy::type_complexity)]
    let rows: Vec<(
        String,
        Option<String>,
        Option<String>,
        String,
        Option<i32>,
        Option<i32>,
        Option<i32>,
        Option<String>,
        Option<chrono::DateTime<chrono::Utc>>,
        Option<chrono::DateTime<chrono::Utc>>,
        chrono::DateTime<chrono::Utc>,
    )> = sqlx::query_as(
        "SELECT id::text, collection, did, status, total_repos, processed_repos, total_records, error, started_at, completed_at, created_at FROM backfill_jobs ORDER BY created_at DESC",
    )
    .fetch_all(&state.db)
    .await
    .map_err(|e| AppError::Internal(format!("failed to list backfill jobs: {e}")))?;

    let jobs: Vec<BackfillJob> = rows
        .into_iter()
        .map(
            |(
                id,
                collection,
                did,
                status,
                total_repos,
                processed_repos,
                total_records,
                error,
                started_at,
                completed_at,
                created_at,
            )| {
                BackfillJob {
                    id,
                    collection,
                    did,
                    status,
                    total_repos,
                    processed_repos,
                    total_records,
                    error,
                    started_at,
                    completed_at,
                    created_at,
                }
            },
        )
        .collect();

    Ok(Json(jobs))
}

// ---------------------------------------------------------------------------
// Admin management endpoints
// ---------------------------------------------------------------------------

#[derive(Deserialize)]
struct CreateAdminBody {
    name: String,
}

#[derive(Serialize)]
struct AdminSummary {
    id: String,
    name: String,
    created_at: chrono::DateTime<chrono::Utc>,
    last_used_at: Option<chrono::DateTime<chrono::Utc>>,
}

/// POST /admin/admins — create a new admin. Returns the API key once.
async fn create_admin(
    State(state): State<AppState>,
    _admin: AdminAuth,
    Json(body): Json<CreateAdminBody>,
) -> Result<(StatusCode, Json<Value>), AppError> {
    let api_key = uuid::Uuid::new_v4().to_string();
    let key_hash = hash_api_key(&api_key);

    let row: (String,) = sqlx::query_as(
        "INSERT INTO admins (name, api_key_hash) VALUES ($1, $2) RETURNING id::text",
    )
    .bind(&body.name)
    .bind(&key_hash)
    .fetch_one(&state.db)
    .await
    .map_err(|e| AppError::Internal(format!("failed to create admin: {e}")))?;

    Ok((
        StatusCode::CREATED,
        Json(serde_json::json!({
            "id": row.0,
            "name": body.name,
            "api_key": api_key,
        })),
    ))
}

/// GET /admin/admins — list all admins (without keys).
async fn list_admins(
    State(state): State<AppState>,
    _admin: AdminAuth,
) -> Result<Json<Vec<AdminSummary>>, AppError> {
    #[allow(clippy::type_complexity)]
    let rows: Vec<(
        String,
        String,
        chrono::DateTime<chrono::Utc>,
        Option<chrono::DateTime<chrono::Utc>>,
    )> = sqlx::query_as(
        "SELECT id::text, name, created_at, last_used_at FROM admins ORDER BY created_at",
    )
    .fetch_all(&state.db)
    .await
    .map_err(|e| AppError::Internal(format!("failed to list admins: {e}")))?;

    let admins: Vec<AdminSummary> = rows
        .into_iter()
        .map(|(id, name, created_at, last_used_at)| AdminSummary {
            id,
            name,
            created_at,
            last_used_at,
        })
        .collect();

    Ok(Json(admins))
}

/// DELETE /admin/admins/:id — remove an admin.
async fn delete_admin(
    State(state): State<AppState>,
    _admin: AdminAuth,
    Path(id): Path<String>,
) -> Result<StatusCode, AppError> {
    let result = sqlx::query("DELETE FROM admins WHERE id::text = $1")
        .bind(&id)
        .execute(&state.db)
        .await
        .map_err(|e| AppError::Internal(format!("failed to delete admin: {e}")))?;

    if result.rows_affected() == 0 {
        return Err(AppError::NotFound(format!("admin '{id}' not found")));
    }

    Ok(StatusCode::NO_CONTENT)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hash_api_key_produces_deterministic_sha256_hex() {
        let h1 = hash_api_key("test-key");
        let h2 = hash_api_key("test-key");
        assert_eq!(h1, h2);
        assert_eq!(h1.len(), 64);
        assert!(h1.chars().all(|c| c.is_ascii_hexdigit()));
    }

    #[test]
    fn hash_api_key_different_inputs_differ() {
        let h1 = hash_api_key("key-a");
        let h2 = hash_api_key("key-b");
        assert_ne!(h1, h2);
    }

    #[test]
    fn hash_api_key_known_value() {
        // SHA-256 of "hello" is well-known
        let hash = hash_api_key("hello");
        assert_eq!(
            hash,
            "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824"
        );
    }
}
