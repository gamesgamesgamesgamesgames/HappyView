use std::collections::HashMap;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicI32, Ordering};

use axum::Json;
use axum::extract::{Path, State};
use axum::http::StatusCode;
use futures_util::stream::{self, StreamExt};
use serde::Deserialize;
use serde_json::Value;
use uuid::Uuid;

use crate::AppState;
use crate::db::{adapt_sql, now_rfc3339};
use crate::error::AppError;
use crate::event_log::{EventLog, Severity, log_event};
use crate::profile;
use crate::record_handler::{self, RecordEvent};

/// Parse rate-limit sleep duration from response headers.
/// Checks `RateLimit-Reset` (Unix timestamp, used by XRPC servers) first,
/// then `retry-after` (seconds), defaulting to 5s.
fn parse_retry_after(headers: &reqwest::header::HeaderMap) -> u64 {
    if let Some(reset) = headers
        .get("ratelimit-reset")
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.parse::<i64>().ok())
    {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs() as i64;
        let wait = (reset - now).max(1) as u64;
        return wait.min(120);
    }

    headers
        .get("retry-after")
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.parse::<u64>().ok())
        .unwrap_or(5)
}

use super::auth::UserAuth;
use super::permissions::Permission;
use super::types::{BackfillJob, CreateBackfillBody};

// ---------------------------------------------------------------------------
// Response types
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

#[derive(Deserialize)]
struct ListRecordsResponse {
    records: Vec<RecordEntry>,
    cursor: Option<String>,
}

#[derive(Deserialize)]
struct RecordEntry {
    uri: String,
    cid: String,
    value: serde_json::Value,
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

async fn set_stage(state: &AppState, job_id: &str, stage: &str) {
    let sql = adapt_sql(
        "UPDATE backfill_jobs SET stage = ? WHERE id = ?",
        state.db_backend,
    );
    let _ = sqlx::query(&sql)
        .bind(stage)
        .bind(job_id)
        .execute(&state.db)
        .await;
}

async fn update_job_counter(state: &AppState, job_id: &str, column: &str, value: i32) {
    let sql = adapt_sql(
        &format!("UPDATE backfill_jobs SET {column} = ? WHERE id = ?"),
        state.db_backend,
    );
    let _ = sqlx::query(&sql)
        .bind(value)
        .bind(job_id)
        .execute(&state.db)
        .await;
}

async fn count_repos(state: &AppState, job_id: &str) -> i32 {
    let sql = adapt_sql(
        "SELECT COUNT(*) FROM backfill_repos WHERE job_id = ?",
        state.db_backend,
    );
    sqlx::query_as::<_, (i32,)>(&sql)
        .bind(job_id)
        .fetch_one(&state.db)
        .await
        .map(|(c,)| c)
        .unwrap_or(0)
}

async fn cleanup_repos(state: &AppState, job_id: &str) {
    let sql = adapt_sql(
        "DELETE FROM backfill_repos WHERE job_id = ?",
        state.db_backend,
    );
    let _ = sqlx::query(&sql).bind(job_id).execute(&state.db).await;
}

async fn fail_job(state: &AppState, job_id: &str, error: &str) {
    let now = now_rfc3339();
    let sql = adapt_sql(
        "UPDATE backfill_jobs SET status = 'failed', completed_at = ?, error = ? WHERE id = ?",
        state.db_backend,
    );
    let _ = sqlx::query(&sql)
        .bind(&now)
        .bind(error)
        .bind(job_id)
        .execute(&state.db)
        .await;
    cleanup_repos(state, job_id).await;
}

async fn is_cancelled(state: &AppState, job_id: &str) -> bool {
    let sql = adapt_sql(
        "SELECT status FROM backfill_jobs WHERE id = ?",
        state.db_backend,
    );
    sqlx::query_as::<_, (String,)>(&sql)
        .bind(job_id)
        .fetch_optional(&state.db)
        .await
        .ok()
        .flatten()
        .is_some_and(|(status,)| status == "cancelling")
}

async fn request_cancel(state: &AppState, job_id: &str) {
    let sql = adapt_sql(
        "UPDATE backfill_jobs SET status = 'cancelling' WHERE id = ? AND status = 'running'",
        state.db_backend,
    );
    let _ = sqlx::query(&sql).bind(job_id).execute(&state.db).await;
}

async fn finalise_cancel(state: &AppState, job_id: &str) {
    let now = now_rfc3339();
    let sql = adapt_sql(
        "UPDATE backfill_jobs SET status = 'cancelled', completed_at = ?, error = 'cancelled by user' WHERE id = ?",
        state.db_backend,
    );
    let _ = sqlx::query(&sql)
        .bind(&now)
        .bind(job_id)
        .execute(&state.db)
        .await;
    cleanup_repos(state, job_id).await;
}

async fn complete_job(
    state: &AppState,
    job_id: &str,
    processed_repos: i32,
    total_records: i32,
    error: Option<&str>,
) {
    let now = now_rfc3339();
    let sql = adapt_sql(
        "UPDATE backfill_jobs SET status = 'completed', stage = 'completed', completed_at = ?, processed_repos = ?, total_records = ?, error = ? WHERE id = ?",
        state.db_backend,
    );
    let _ = sqlx::query(&sql)
        .bind(&now)
        .bind(processed_repos)
        .bind(total_records)
        .bind(error)
        .bind(job_id)
        .execute(&state.db)
        .await;
    cleanup_repos(state, job_id).await;
}

// ---------------------------------------------------------------------------
// Phase 1: Discover repos via relay
// ---------------------------------------------------------------------------

async fn run_discovery_phase(
    state: &AppState,
    job_id: &str,
    collections: &[String],
    specific_did: Option<&str>,
) {
    set_stage(state, job_id, "discovering_repos").await;

    if let Some(did) = specific_did {
        let sql = adapt_sql(
            "INSERT INTO backfill_repos (job_id, did) VALUES (?, ?) ON CONFLICT DO NOTHING",
            state.db_backend,
        );
        let _ = sqlx::query(&sql)
            .bind(job_id)
            .bind(did)
            .execute(&state.db)
            .await;
    } else {
        for collection in collections {
            if is_cancelled(state, job_id).await {
                return;
            }
            if let Err(e) = discover_repos_from_relay(state, job_id, collection).await {
                tracing::warn!(collection, error = %e, "failed to discover repos, skipping");
            }
        }
    }

    let total = count_repos(state, job_id).await;
    update_job_counter(state, job_id, "total_repos", total).await;
}

async fn discover_repos_from_relay(
    state: &AppState,
    job_id: &str,
    collection: &str,
) -> Result<(), String> {
    let base = state.config.relay_url.trim_end_matches('/');
    let mut cursor: Option<String> = None;

    loop {
        let mut url = format!(
            "{base}/xrpc/com.atproto.sync.listReposByCollection?collection={collection}&limit=1000"
        );
        if let Some(ref c) = cursor {
            url.push_str(&format!("&cursor={c}"));
        }

        let resp = loop {
            let r = state
                .http
                .get(&url)
                .send()
                .await
                .map_err(|e| format!("relay request failed: {e}"))?;

            if r.status() == reqwest::StatusCode::TOO_MANY_REQUESTS {
                let wait = parse_retry_after(r.headers());
                tracing::warn!(collection, wait, "rate limited by relay, sleeping");
                tokio::time::sleep(tokio::time::Duration::from_secs(wait)).await;
                continue;
            }

            break r;
        };

        if !resp.status().is_success() {
            return Err(format!("relay returned {}", resp.status()));
        }

        let body: ListReposResponse = resp
            .json()
            .await
            .map_err(|e| format!("invalid relay response: {e}"))?;

        let page_count = body.repos.len();

        for repo in &body.repos {
            let sql = adapt_sql(
                "INSERT INTO backfill_repos (job_id, did) VALUES (?, ?) ON CONFLICT DO NOTHING",
                state.db_backend,
            );
            let _ = sqlx::query(&sql)
                .bind(job_id)
                .bind(&repo.did)
                .execute(&state.db)
                .await;
        }

        let total = count_repos(state, job_id).await;
        update_job_counter(state, job_id, "total_repos", total).await;

        if is_cancelled(state, job_id).await {
            return Ok(());
        }

        match body.cursor {
            Some(c) if page_count > 0 => cursor = Some(c),
            _ => break,
        }
    }

    Ok(())
}

// ---------------------------------------------------------------------------
// Phase 2: Resolve PDS endpoints
// ---------------------------------------------------------------------------

async fn run_resolution_phase(state: &AppState, job_id: &str) {
    set_stage(state, job_id, "resolving_pds").await;

    let sql = adapt_sql(
        "SELECT did FROM backfill_repos WHERE job_id = ? AND pds_endpoint IS NULL",
        state.db_backend,
    );
    let unresolved: Vec<(String,)> = sqlx::query_as(&sql)
        .bind(job_id)
        .fetch_all(&state.db)
        .await
        .unwrap_or_default();

    let sql = adapt_sql(
        "SELECT COUNT(*) FROM backfill_repos WHERE job_id = ? AND pds_endpoint IS NOT NULL",
        state.db_backend,
    );
    let already_resolved: i32 = sqlx::query_as::<_, (i32,)>(&sql)
        .bind(job_id)
        .fetch_one(&state.db)
        .await
        .map(|(c,)| c)
        .unwrap_or(0);

    let mut resolved_count = already_resolved;

    for (did,) in &unresolved {
        match profile::resolve_pds_endpoint(&state.http, &state.config.plc_url, did).await {
            Ok(pds) => {
                let sql = adapt_sql(
                    "UPDATE backfill_repos SET pds_endpoint = ? WHERE job_id = ? AND did = ?",
                    state.db_backend,
                );
                let _ = sqlx::query(&sql)
                    .bind(&pds)
                    .bind(job_id)
                    .bind(did)
                    .execute(&state.db)
                    .await;
            }
            Err(e) => {
                tracing::warn!(did, error = %e, "failed to resolve PDS endpoint, skipping DID");
            }
        }
        resolved_count += 1;
        if resolved_count % 100 == 0 {
            update_job_counter(state, job_id, "processed_repos", resolved_count).await;
            if is_cancelled(state, job_id).await {
                return;
            }
        }
    }

    update_job_counter(state, job_id, "processed_repos", resolved_count).await;
}

// ---------------------------------------------------------------------------
// Phase 3: Fetch records from PDS instances
// ---------------------------------------------------------------------------

async fn run_fetching_phase(state: &AppState, job_id: &str, collections: &[String]) -> (i32, i32) {
    set_stage(state, job_id, "fetching_records").await;

    // Load pending repos grouped by PDS
    let sql = adapt_sql(
        "SELECT did, pds_endpoint FROM backfill_repos WHERE job_id = ? AND status = 'pending' AND pds_endpoint IS NOT NULL",
        state.db_backend,
    );
    let rows: Vec<(String, String)> = sqlx::query_as(&sql)
        .bind(job_id)
        .fetch_all(&state.db)
        .await
        .unwrap_or_default();

    let mut pds_to_dids: HashMap<String, Vec<String>> = HashMap::new();
    for (did, pds) in rows {
        pds_to_dids.entry(pds).or_default().push(did);
    }

    // Count already-completed repos for accurate progress
    let sql = adapt_sql(
        "SELECT COUNT(*) FROM backfill_repos WHERE job_id = ? AND status = 'completed'",
        state.db_backend,
    );
    let already_completed: i32 = sqlx::query_as::<_, (i32,)>(&sql)
        .bind(job_id)
        .fetch_one(&state.db)
        .await
        .map(|(c,)| c)
        .unwrap_or(0);

    // Reset processed_repos for the fetching phase
    update_job_counter(state, job_id, "processed_repos", already_completed).await;

    let processed_repos = Arc::new(AtomicI32::new(already_completed));
    let total_records = Arc::new(AtomicI32::new(0));
    let cancelled = Arc::new(AtomicBool::new(false));
    let state = Arc::new(state.clone());
    let collections = Arc::new(collections.to_vec());
    let job_id_arc = Arc::new(job_id.to_string());

    let pds_entries: Vec<(String, Vec<String>)> = pds_to_dids.into_iter().collect();

    stream::iter(pds_entries)
        .for_each_concurrent(10, |(pds_endpoint, dids)| {
            let state = Arc::clone(&state);
            let collections = Arc::clone(&collections);
            let processed_repos = Arc::clone(&processed_repos);
            let total_records = Arc::clone(&total_records);
            let cancelled = Arc::clone(&cancelled);
            let job_id = Arc::clone(&job_id_arc);

            async move {
                stream::iter(dids)
                    .for_each_concurrent(3, |did| {
                        let state = Arc::clone(&state);
                        let collections = Arc::clone(&collections);
                        let processed_repos = Arc::clone(&processed_repos);
                        let total_records = Arc::clone(&total_records);
                        let cancelled = Arc::clone(&cancelled);
                        let pds_endpoint = pds_endpoint.clone();
                        let job_id = Arc::clone(&job_id);

                        async move {
                            if cancelled.load(Ordering::Relaxed) {
                                return;
                            }

                            for collection in collections.iter() {
                                match fetch_records_from_pds(
                                    &state,
                                    &pds_endpoint,
                                    &did,
                                    collection,
                                )
                                .await
                                {
                                    Ok(count) => {
                                        total_records
                                            .fetch_add(count as i32, Ordering::Relaxed);
                                    }
                                    Err(e) => {
                                        tracing::warn!(
                                            did,
                                            collection,
                                            pds = %pds_endpoint,
                                            error = %e,
                                            "failed to fetch records from PDS"
                                        );
                                    }
                                }
                            }

                            // Mark DID as completed
                            let sql = adapt_sql(
                                "UPDATE backfill_repos SET status = 'completed' WHERE job_id = ? AND did = ?",
                                state.db_backend,
                            );
                            let _ = sqlx::query(&sql)
                                .bind(job_id.as_str())
                                .bind(&did)
                                .execute(&state.db)
                                .await;

                            let repos = processed_repos.fetch_add(1, Ordering::Relaxed) + 1;

                            if repos % 100 == 0 {
                                let records = total_records.load(Ordering::Relaxed);
                                let backend = state.db_backend;
                                let sql = adapt_sql(
                                    "UPDATE backfill_jobs SET processed_repos = ?, total_records = ? WHERE id = ?",
                                    backend,
                                );
                                let _ = sqlx::query(&sql)
                                    .bind(repos)
                                    .bind(records)
                                    .bind(job_id.as_str())
                                    .execute(&state.db)
                                    .await;

                                if is_cancelled(&state, job_id.as_str()).await {
                                    cancelled.store(true, Ordering::Relaxed);
                                }
                            }
                        }
                    })
                    .await;
            }
        })
        .await;

    let final_repos = processed_repos.load(Ordering::Relaxed);
    let final_records = total_records.load(Ordering::Relaxed);

    // Persist final counts so they're accurate regardless of batch size
    let sql = adapt_sql(
        "UPDATE backfill_jobs SET processed_repos = ?, total_records = ? WHERE id = ?",
        state.db_backend,
    );
    let _ = sqlx::query(&sql)
        .bind(final_repos)
        .bind(final_records)
        .bind(job_id)
        .execute(&state.db)
        .await;

    (final_repos, final_records)
}

/// Fetch all records for a given DID and collection from a PDS via
/// `com.atproto.repo.listRecords`, paginating and handling rate limits.
async fn fetch_records_from_pds(
    state: &AppState,
    pds_endpoint: &str,
    did: &str,
    collection: &str,
) -> Result<u32, String> {
    let base = pds_endpoint.trim_end_matches('/');
    let mut cursor: Option<String> = None;
    let mut count: u32 = 0;

    loop {
        let mut url = format!(
            "{base}/xrpc/com.atproto.repo.listRecords?repo={did}&collection={collection}&limit=100"
        );
        if let Some(ref c) = cursor {
            url.push_str(&format!("&cursor={c}"));
        }

        let resp = state
            .http
            .get(&url)
            .send()
            .await
            .map_err(|e| format!("PDS request failed: {e}"))?;

        if resp.status() == reqwest::StatusCode::TOO_MANY_REQUESTS {
            let wait = parse_retry_after(resp.headers());
            tracing::warn!(did, collection, wait, "rate limited by PDS, sleeping");
            tokio::time::sleep(tokio::time::Duration::from_secs(wait)).await;
            continue;
        }

        if !resp.status().is_success() {
            return Err(format!("PDS returned {}", resp.status()));
        }

        let body: ListRecordsResponse = resp
            .json()
            .await
            .map_err(|e| format!("invalid PDS response: {e}"))?;

        let page_count = body.records.len();

        for entry in &body.records {
            let rkey = entry.uri.rsplit('/').next().unwrap_or_default().to_string();

            let event = RecordEvent {
                did: did.to_string(),
                collection: collection.to_string(),
                rkey,
                action: "create".to_string(),
                record: Some(entry.value.clone()),
                cid: Some(entry.cid.clone()),
            };

            record_handler::handle_record_event(state, &event).await;
            count += 1;
        }

        match body.cursor {
            Some(c) if page_count > 0 => cursor = Some(c),
            _ => break,
        }
    }

    Ok(count)
}

// ---------------------------------------------------------------------------
// Background backfill worker
// ---------------------------------------------------------------------------

async fn run_backfill_job(state: AppState, job_id: String) {
    let backend = state.db_backend;

    // Load job metadata
    let sql = adapt_sql(
        "SELECT collection, did, stage FROM backfill_jobs WHERE id = ?",
        backend,
    );
    let job: Option<(Option<String>, Option<String>, String)> = sqlx::query_as(&sql)
        .bind(&job_id)
        .fetch_optional(&state.db)
        .await
        .ok()
        .flatten();

    let Some((collection, did, stage)) = job else {
        tracing::error!(job_id, "backfill job not found");
        return;
    };

    // Determine target collections
    let collections: Vec<String> = if let Some(ref col) = collection {
        let lexicon_exists: bool = state
            .lexicons
            .get(col)
            .await
            .is_some_and(|lex| lex.lexicon_type == crate::lexicon::LexiconType::Record);
        if !lexicon_exists {
            let error = format!("no record-type lexicon registered for collection '{col}'");
            fail_job(&state, &job_id, &error).await;
            return;
        }
        vec![col.clone()]
    } else {
        let sql = adapt_sql(
            "SELECT id FROM lexicons WHERE json_extract(lexicon_json, '$.defs.main.type') = 'record'",
            backend,
        );
        let rows: Vec<(String,)> = match sqlx::query_as(&sql).fetch_all(&state.db).await {
            Ok(rows) => rows,
            Err(e) => {
                let error = format!("failed to query backfill-eligible lexicons: {e}");
                fail_job(&state, &job_id, &error).await;
                return;
            }
        };
        rows.into_iter().map(|(id,)| id).collect()
    };

    if collections.is_empty() {
        complete_job(
            &state,
            &job_id,
            0,
            0,
            Some("no backfill-eligible collections"),
        )
        .await;
        return;
    }

    // Run phases, skipping those already completed
    if matches!(stage.as_str(), "pending" | "discovering_repos") {
        run_discovery_phase(&state, &job_id, &collections, did.as_deref()).await;

        if is_cancelled(&state, &job_id).await {
            tracing::info!(job_id, "backfill job cancelled");
            finalise_cancel(&state, &job_id).await;
            return;
        }

        let total = count_repos(&state, &job_id).await;
        if total == 0 {
            complete_job(&state, &job_id, 0, 0, None).await;
            log_event(
                &state.db,
                EventLog {
                    event_type: "backfill.completed".to_string(),
                    severity: Severity::Info,
                    actor_did: None,
                    subject: collection.clone(),
                    detail: serde_json::json!({
                        "job_id": job_id,
                        "total_repos": 0,
                        "total_records": 0,
                    }),
                },
                backend,
            )
            .await;
            return;
        }
    }

    if matches!(
        stage.as_str(),
        "pending" | "discovering_repos" | "resolving_pds"
    ) {
        run_resolution_phase(&state, &job_id).await;

        if is_cancelled(&state, &job_id).await {
            tracing::info!(job_id, "backfill job cancelled");
            finalise_cancel(&state, &job_id).await;
            return;
        }
    }

    let (final_processed, final_records) = run_fetching_phase(&state, &job_id, &collections).await;

    if is_cancelled(&state, &job_id).await {
        tracing::info!(job_id, "backfill job cancelled");
        finalise_cancel(&state, &job_id).await;
        return;
    }

    complete_job(&state, &job_id, final_processed, final_records, None).await;

    log_event(
        &state.db,
        EventLog {
            event_type: "backfill.completed".to_string(),
            severity: Severity::Info,
            actor_did: None,
            subject: collection,
            detail: serde_json::json!({
                "job_id": job_id,
                "total_repos": final_processed,
                "total_records": final_records,
            }),
        },
        backend,
    )
    .await;
}

// ---------------------------------------------------------------------------
// Admin handlers
// ---------------------------------------------------------------------------

/// POST /admin/backfill — create a backfill job and spawn background work.
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
        "INSERT INTO backfill_jobs (id, collection, did, status, stage, started_at, created_at) VALUES (?, ?, ?, 'running', 'pending', ?, ?) RETURNING id",
        backend,
    );
    let row: (String,) = sqlx::query_as(&sql)
        .bind(&job_id)
        .bind(&body.collection)
        .bind(&body.did)
        .bind(&now)
        .bind(&now)
        .fetch_one(&state.db)
        .await
        .map_err(|e| AppError::Internal(format!("failed to create backfill job: {e}")))?;

    let job_id = row.0.clone();

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

    let spawn_state = state.clone();
    let spawn_job_id = job_id.clone();
    tokio::spawn(async move {
        run_backfill_job(spawn_state, spawn_job_id).await;
    });

    Ok((
        StatusCode::CREATED,
        Json(serde_json::json!({
            "id": job_id,
            "status": "running",
        })),
    ))
}

/// POST /admin/backfill/{id}/cancel — cancel a running backfill job.
pub(super) async fn cancel_backfill(
    State(state): State<AppState>,
    admin: UserAuth,
    Path(job_id): Path<String>,
) -> Result<Json<Value>, AppError> {
    admin.require(Permission::BackfillCreate).await?;

    let sql = adapt_sql(
        "SELECT status FROM backfill_jobs WHERE id = ?",
        state.db_backend,
    );
    let row: Option<(String,)> = sqlx::query_as(&sql)
        .bind(&job_id)
        .fetch_optional(&state.db)
        .await
        .map_err(|e| AppError::Internal(format!("failed to query backfill job: {e}")))?;

    match row {
        None => Err(AppError::NotFound("backfill job not found".into())),
        Some((status,)) if status != "running" => Err(AppError::BadRequest(format!(
            "job is not running (status: {status})"
        ))),
        Some(_) => {
            request_cancel(&state, &job_id).await;
            log_event(
                &state.db,
                EventLog {
                    event_type: "backfill.cancelling".to_string(),
                    severity: Severity::Info,
                    actor_did: Some(admin.did.clone()),
                    subject: None,
                    detail: serde_json::json!({ "job_id": job_id }),
                },
                state.db_backend,
            )
            .await;
            Ok(Json(
                serde_json::json!({ "id": job_id, "status": "cancelling" }),
            ))
        }
    }
}

/// GET /admin/backfill/status — list all backfill jobs.
pub(super) async fn backfill_status(
    State(state): State<AppState>,
    auth: UserAuth,
) -> Result<Json<Vec<BackfillJob>>, AppError> {
    auth.require(Permission::BackfillRead).await?;
    let backend = state.db_backend;

    let sql = adapt_sql(
        "SELECT id, collection, did, status, stage, total_repos, processed_repos, total_records, error, started_at, completed_at, created_at FROM backfill_jobs ORDER BY created_at DESC",
        backend,
    );
    #[allow(clippy::type_complexity)]
    let rows: Vec<(
        String,
        Option<String>,
        Option<String>,
        String,
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
                stage,
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
                    stage,
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
// Startup resumption
// ---------------------------------------------------------------------------

/// Resume any backfill jobs that were running when the server last stopped.
/// Jobs stuck in `cancelling` are finalised immediately.
pub async fn resume_backfill_jobs(state: &AppState) {
    let sql = adapt_sql(
        "SELECT id, status FROM backfill_jobs WHERE status IN ('running', 'cancelling')",
        state.db_backend,
    );
    let rows: Vec<(String, String)> = sqlx::query_as(&sql)
        .fetch_all(&state.db)
        .await
        .unwrap_or_default();

    for (job_id, status) in rows {
        if status == "cancelling" {
            tracing::info!(
                job_id,
                "finalising cancelled backfill job from previous run"
            );
            finalise_cancel(state, &job_id).await;
        } else {
            tracing::info!(job_id, "resuming interrupted backfill job");
            let spawn_state = state.clone();
            tokio::spawn(async move {
                run_backfill_job(spawn_state, job_id).await;
            });
        }
    }
}
