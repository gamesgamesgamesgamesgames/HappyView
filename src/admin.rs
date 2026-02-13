use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::routing::{get, post};
use axum::{Json, Router};
use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::error::AppError;
use crate::lexicon::{LexiconType, ParsedLexicon};
use crate::AppState;

// ---------------------------------------------------------------------------
// Admin auth middleware
// ---------------------------------------------------------------------------

/// Axum middleware layer that rejects requests without a valid admin secret.
pub fn admin_routes(_state: AppState) -> Router<AppState> {
    Router::new()
        .route("/lexicons", post(upload_lexicon).get(list_lexicons))
        .route("/lexicons/{id}", get(get_lexicon).delete(delete_lexicon))
        .route("/stats", get(stats))
}

/// Extract and validate the admin Bearer token from request headers.
fn extract_admin_token(headers: &axum::http::HeaderMap, secret: &Option<String>) -> Result<(), AppError> {
    let secret = secret
        .as_ref()
        .ok_or_else(|| AppError::Auth("admin API is not configured".into()))?;

    let header = headers
        .get("authorization")
        .and_then(|v| v.to_str().ok())
        .ok_or_else(|| AppError::Auth("missing Authorization header".into()))?;

    let token = header
        .strip_prefix("Bearer ")
        .ok_or_else(|| AppError::Auth("invalid Authorization scheme".into()))?;

    if token != secret {
        return Err(AppError::Auth("invalid admin secret".into()));
    }

    Ok(())
}

/// Axum extractor for admin auth — validates Bearer token against ADMIN_SECRET.
pub struct AdminAuth;

impl axum::extract::FromRequestParts<AppState> for AdminAuth {
    type Rejection = AppError;

    async fn from_request_parts(
        parts: &mut axum::http::request::Parts,
        state: &AppState,
    ) -> Result<Self, Self::Rejection> {
        extract_admin_token(&parts.headers, &state.config.admin_secret)?;
        Ok(AdminAuth)
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
        .ok_or_else(|| AppError::BadRequest("lexicon JSON must have a numeric 'lexicon' field".into()))?;

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
    ParsedLexicon::parse(body.lexicon_json.clone(), 1)
        .map_err(|e| AppError::BadRequest(format!("failed to parse lexicon: {e}")))?;

    // Upsert into database
    let row: (i32,) = sqlx::query_as(
        r#"
        INSERT INTO lexicons (id, lexicon_json, backfill)
        VALUES ($1, $2, $3)
        ON CONFLICT (id) DO UPDATE SET
            lexicon_json = EXCLUDED.lexicon_json,
            backfill = EXCLUDED.backfill,
            revision = lexicons.revision + 1,
            updated_at = NOW()
        RETURNING revision
        "#,
    )
    .bind(&id)
    .bind(&body.lexicon_json)
    .bind(body.backfill)
    .fetch_one(&state.db)
    .await
    .map_err(|e| AppError::Internal(format!("failed to upsert lexicon: {e}")))?;

    let revision = row.0;

    // Update in-memory registry with correct revision
    let parsed = ParsedLexicon::parse(body.lexicon_json, revision)
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
            let lexicon_type = ParsedLexicon::parse(json, revision)
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
