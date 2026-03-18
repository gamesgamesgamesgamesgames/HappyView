use axum::Json;
use axum::extract::State;
use axum::http::StatusCode;
use serde::Deserialize;
use serde_json::Value;
use uuid::Uuid;

use crate::AppState;
use crate::db::{adapt_sql, now_rfc3339};
use crate::error::AppError;
use crate::event_log::{EventLog, Severity, log_event};
use crate::tap;

use super::auth::UserAuth;
use super::permissions::Permission;
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
    admin: UserAuth,
    Json(body): Json<CreateBackfillBody>,
) -> Result<(StatusCode, Json<Value>), AppError> {
    admin.require(Permission::BackfillCreate).await?;
    let backend = state.db_backend;

    let now = now_rfc3339();
    let job_id = Uuid::new_v4().to_string();
    let sql = adapt_sql(
        "INSERT INTO backfill_jobs (id, collection, did, created_at) VALUES (?, ?, ?, ?) RETURNING id",
        backend,
    );
    let row: (String,) = sqlx::query_as(&sql)
        .bind(&job_id)
        .bind(&body.collection)
        .bind(&body.did)
        .bind(&now)
        .fetch_one(&state.db)
        .await
        .map_err(|e| AppError::Internal(format!("failed to create backfill job: {e}")))?;

    let job_id = row.0.clone();

    let now = now_rfc3339();
    let sql = adapt_sql(
        "UPDATE backfill_jobs SET status = 'running', started_at = ? WHERE id = ?",
        backend,
    );
    let _ = sqlx::query(&sql)
        .bind(&now)
        .bind(&job_id)
        .execute(&state.db)
        .await;

    log_event(
        &state.db,
        EventLog {
            event_type: "backfill.started".to_string(),
            severity: Severity::Info,
            actor_did: Some(admin.did.clone()),
            subject: body.collection.clone(),
            detail: serde_json::json!({
                "job_id": job_id.clone(),
            }),
        },
        backend,
    )
    .await;

    let collections: Vec<String> = if let Some(ref col) = body.collection {
        let lexicon_exists: bool = state
            .lexicons
            .get(col)
            .await
            .is_some_and(|lex| lex.lexicon_type == crate::lexicon::LexiconType::Record);
        if !lexicon_exists {
            let error = format!("no record-type lexicon registered for collection '{col}'");
            let now = now_rfc3339();
            let sql = adapt_sql(
                "UPDATE backfill_jobs SET status = 'failed', completed_at = ?, error = ? WHERE id = ?",
                backend,
            );
            let _ = sqlx::query(&sql)
                .bind(&now)
                .bind(&error)
                .bind(&job_id)
                .execute(&state.db)
                .await;

            return Ok((
                StatusCode::CREATED,
                Json(serde_json::json!({
                    "id": job_id,
                    "status": "failed",
                    "error": error,
                })),
            ));
        }
        vec![col.clone()]
    } else {
        let sql = adapt_sql(
            "SELECT id FROM lexicons WHERE backfill = 1 AND json_extract(lexicon_json, '$.defs.main.type') = 'record'",
            backend,
        );
        let rows: Vec<(String,)> =
            sqlx::query_as(&sql)
                .fetch_all(&state.db)
                .await
                .map_err(|e| {
                    AppError::Internal(format!("failed to query backfill-eligible lexicons: {e}"))
                })?;
        rows.into_iter().map(|(id,)| id).collect()
    };

    if collections.is_empty() {
        let now = now_rfc3339();
        let sql = adapt_sql(
            "UPDATE backfill_jobs SET status = 'completed', completed_at = ?, error = 'no backfill-eligible collections' WHERE id = ?",
            backend,
        );
        let _ = sqlx::query(&sql)
            .bind(&now)
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

    all_dids.sort();
    all_dids.dedup();

    let total_repos = all_dids.len() as i32;

    let sql = adapt_sql(
        "UPDATE backfill_jobs SET total_repos = ? WHERE id = ?",
        backend,
    );
    let _ = sqlx::query(&sql)
        .bind(total_repos)
        .bind(&job_id)
        .execute(&state.db)
        .await;

    for chunk in all_dids.chunks(1000) {
        if let Err(e) = tap::remove_repos(
            &state.http,
            &state.config.tap_url,
            state.config.tap_admin_password.as_deref(),
            chunk,
        )
        .await
        {
            tracing::warn!(error = %e, "failed to remove repos from tap, continuing");
        }
    }

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
                let now = now_rfc3339();
                let sql = adapt_sql(
                    "UPDATE backfill_jobs SET status = 'failed', completed_at = ?, error = ? WHERE id = ?",
                    backend,
                );
                let _ = sqlx::query(&sql)
                    .bind(&now)
                    .bind(&e)
                    .bind(&job_id)
                    .execute(&state.db)
                    .await;

                log_event(
                    &state.db,
                    EventLog {
                        event_type: "backfill.failed".to_string(),
                        severity: Severity::Error,
                        actor_did: None,
                        subject: body.collection.clone(),
                        detail: serde_json::json!({
                            "job_id": job_id.clone(),
                            "error": e,
                        }),
                    },
                    backend,
                )
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

    let now = now_rfc3339();
    let sql = adapt_sql(
        "UPDATE backfill_jobs SET status = 'completed', completed_at = ?, processed_repos = ? WHERE id = ?",
        backend,
    );
    let _ = sqlx::query(&sql)
        .bind(&now)
        .bind(total_repos)
        .bind(&job_id)
        .execute(&state.db)
        .await;

    log_event(
        &state.db,
        EventLog {
            event_type: "backfill.completed".to_string(),
            severity: Severity::Info,
            actor_did: None,
            subject: body.collection.clone(),
            detail: serde_json::json!({
                "job_id": job_id.clone(),
                "total_repos": total_repos,
            }),
        },
        backend,
    )
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
    auth: UserAuth,
) -> Result<Json<Vec<BackfillJob>>, AppError> {
    auth.require(Permission::BackfillRead).await?;
    let backend = state.db_backend;

    let sql = adapt_sql(
        "SELECT id, collection, did, status, total_repos, processed_repos, total_records, error, started_at, completed_at, created_at FROM backfill_jobs ORDER BY created_at DESC",
        backend,
    );
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
        Option<String>,
        Option<String>,
        String,
    )> = sqlx::query_as(&sql)
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
