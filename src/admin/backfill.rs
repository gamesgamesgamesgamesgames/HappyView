use axum::Json;
use axum::extract::State;
use axum::http::StatusCode;
use serde::Deserialize;
use serde_json::Value;

use crate::AppState;
use crate::error::AppError;
use crate::tap;

use super::auth::AdminAuth;
use super::types::{BackfillJob, CreateBackfillBody};

// ---------------------------------------------------------------------------
// Relay discovery (reused from old backfill module)
// ---------------------------------------------------------------------------

#[derive(Deserialize)]
struct ListReposResponse {
    repos: Vec<RepoEntry>,
    cursor: Option<String>,
}

#[derive(Deserialize)]
struct RepoEntry {
    did: String,
}

/// Discover all DIDs that have records in `collection` via the relay's
/// `com.atproto.sync.listReposByCollection` endpoint. Paginates until done.
async fn list_repos_by_collection(
    http: &reqwest::Client,
    relay_url: &str,
    collection: &str,
) -> Result<Vec<String>, String> {
    let base = relay_url.trim_end_matches('/');
    let mut dids = Vec::new();
    let mut cursor: Option<String> = None;

    loop {
        let mut url = format!(
            "{base}/xrpc/com.atproto.sync.listReposByCollection?collection={collection}&limit=1000"
        );
        if let Some(ref c) = cursor {
            url.push_str(&format!("&cursor={c}"));
        }

        let resp = http
            .get(&url)
            .send()
            .await
            .map_err(|e| format!("relay request failed: {e}"))?;

        if !resp.status().is_success() {
            return Err(format!("relay returned {}", resp.status()));
        }

        let body: ListReposResponse = resp
            .json()
            .await
            .map_err(|e| format!("invalid relay response: {e}"))?;

        let page_count = body.repos.len();
        for repo in body.repos {
            dids.push(repo.did);
        }

        match body.cursor {
            Some(c) if page_count > 0 => cursor = Some(c),
            _ => break,
        }
    }

    Ok(dids)
}

// ---------------------------------------------------------------------------
// Admin handlers
// ---------------------------------------------------------------------------

/// POST /admin/backfill — create a backfill job, discover repos, and add them to Tap.
pub(super) async fn create_backfill(
    State(state): State<AppState>,
    _admin: AdminAuth,
    Json(body): Json<CreateBackfillBody>,
) -> Result<(StatusCode, Json<Value>), AppError> {
    // Create a backfill_jobs record for tracking/audit.
    let row: (String,) = sqlx::query_as(
        "INSERT INTO backfill_jobs (collection, did) VALUES ($1, $2) RETURNING id::text",
    )
    .bind(&body.collection)
    .bind(&body.did)
    .fetch_one(&state.db)
    .await
    .map_err(|e| AppError::Internal(format!("failed to create backfill job: {e}")))?;

    let job_id = row.0.clone();

    // Mark as running.
    let _ = sqlx::query(
        "UPDATE backfill_jobs SET status = 'running', started_at = NOW() WHERE id::text = $1",
    )
    .bind(&job_id)
    .execute(&state.db)
    .await;

    // Determine target collections.
    let collections: Vec<String> = if let Some(ref col) = body.collection {
        vec![col.clone()]
    } else {
        let rows: Vec<(String,)> = sqlx::query_as(
            "SELECT id FROM lexicons WHERE backfill = TRUE AND lexicon_json->'defs'->'main'->>'type' = 'record'",
        )
        .fetch_all(&state.db)
        .await
        .map_err(|e| AppError::Internal(format!("failed to query backfill-eligible lexicons: {e}")))?;
        rows.into_iter().map(|(id,)| id).collect()
    };

    if collections.is_empty() {
        let _ = sqlx::query(
            "UPDATE backfill_jobs SET status = 'completed', completed_at = NOW(), error = 'no backfill-eligible collections' WHERE id::text = $1",
        )
        .bind(&job_id)
        .execute(&state.db)
        .await;

        return Ok((
            StatusCode::CREATED,
            Json(serde_json::json!({
                "id": job_id,
                "status": "completed",
                "error": "no backfill-eligible collections",
            })),
        ));
    }

    // Discover repos and add them to Tap.
    let mut all_dids = Vec::new();

    for collection in &collections {
        let dids = if let Some(ref did) = body.did {
            vec![did.clone()]
        } else {
            match list_repos_by_collection(&state.http, &state.config.relay_url, collection).await {
                Ok(dids) => dids,
                Err(e) => {
                    tracing::warn!(collection, error = %e, "failed to discover repos, skipping");
                    continue;
                }
            }
        };

        all_dids.extend(dids);
    }

    // Deduplicate DIDs.
    all_dids.sort();
    all_dids.dedup();

    let total_repos = all_dids.len() as i32;

    // Update job with total repos.
    let _ = sqlx::query("UPDATE backfill_jobs SET total_repos = $2 WHERE id::text = $1")
        .bind(&job_id)
        .bind(total_repos)
        .execute(&state.db)
        .await;

    // Add repos to Tap in batches.
    if !all_dids.is_empty() {
        for chunk in all_dids.chunks(1000) {
            if let Err(e) = tap::add_repos(
                &state.http,
                &state.config.tap_url,
                state.config.tap_admin_password.as_deref(),
                chunk,
            )
            .await
            {
                tracing::warn!(error = %e, "failed to add repos to tap");
                let _ = sqlx::query(
                    "UPDATE backfill_jobs SET status = 'failed', completed_at = NOW(), error = $2 WHERE id::text = $1",
                )
                .bind(&job_id)
                .bind(&e)
                .execute(&state.db)
                .await;

                return Ok((
                    StatusCode::CREATED,
                    Json(serde_json::json!({
                        "id": job_id,
                        "status": "failed",
                        "error": e,
                    })),
                ));
            }
        }
    }

    // Mark as completed (Tap handles the actual backfill asynchronously).
    let _ = sqlx::query(
        "UPDATE backfill_jobs SET status = 'completed', completed_at = NOW(), processed_repos = $2 WHERE id::text = $1",
    )
    .bind(&job_id)
    .bind(total_repos)
    .execute(&state.db)
    .await;

    Ok((
        StatusCode::CREATED,
        Json(serde_json::json!({
            "id": job_id,
            "status": "completed",
            "total_repos": total_repos,
        })),
    ))
}

/// GET /admin/backfill/status — list all backfill jobs.
pub(super) async fn backfill_status(
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
