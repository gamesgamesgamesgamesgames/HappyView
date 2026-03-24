use std::collections::HashMap;
use std::sync::Arc;
use std::sync::atomic::{AtomicI32, Ordering};

use axum::Json;
use axum::extract::State;
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

// ---------------------------------------------------------------------------
// PDS record types
// ---------------------------------------------------------------------------

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
// PDS record fetching
// ---------------------------------------------------------------------------

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

        // Handle rate limiting
        if resp.status() == reqwest::StatusCode::TOO_MANY_REQUESTS {
            let retry_after = resp
                .headers()
                .get("retry-after")
                .and_then(|v| v.to_str().ok())
                .and_then(|v| v.parse::<u64>().ok())
                .unwrap_or(5);
            tracing::warn!(
                did,
                collection,
                retry_after,
                "rate limited by PDS, sleeping"
            );
            tokio::time::sleep(tokio::time::Duration::from_secs(retry_after)).await;
            continue; // retry same page
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
        "INSERT INTO backfill_jobs (id, collection, did, status, started_at, created_at) VALUES (?, ?, ?, 'running', ?, ?) RETURNING id",
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

    // Clone what we need and spawn the background job
    let spawn_state = state.clone();
    let spawn_job_id = job_id.clone();
    let spawn_body = body.clone();
    tokio::spawn(async move {
        run_backfill_job(spawn_state, spawn_job_id, spawn_body).await;
    });

    Ok((
        StatusCode::CREATED,
        Json(serde_json::json!({
            "id": job_id,
            "status": "running",
        })),
    ))
}

// ---------------------------------------------------------------------------
// Background backfill worker
// ---------------------------------------------------------------------------

async fn run_backfill_job(state: AppState, job_id: String, body: CreateBackfillBody) {
    let backend = state.db_backend;

    // Determine target collections
    let collections: Vec<String> = if let Some(ref col) = body.collection {
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
            "SELECT id FROM lexicons WHERE backfill = 1 AND json_extract(lexicon_json, '$.defs.main.type') = 'record'",
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

    // Discover DIDs
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

    // Update total_repos in DB
    let sql = adapt_sql(
        "UPDATE backfill_jobs SET total_repos = ? WHERE id = ?",
        backend,
    );
    let _ = sqlx::query(&sql)
        .bind(total_repos)
        .bind(&job_id)
        .execute(&state.db)
        .await;

    if all_dids.is_empty() {
        complete_job(&state, &job_id, 0, 0, None).await;

        log_event(
            &state.db,
            EventLog {
                event_type: "backfill.completed".to_string(),
                severity: Severity::Info,
                actor_did: None,
                subject: body.collection.clone(),
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

    // Resolve DIDs to PDS endpoints and group by PDS
    let mut pds_to_dids: HashMap<String, Vec<String>> = HashMap::new();

    for did in &all_dids {
        match profile::resolve_pds_endpoint(&state.http, &state.config.plc_url, did).await {
            Ok(pds) => {
                pds_to_dids.entry(pds).or_default().push(did.clone());
            }
            Err(e) => {
                tracing::warn!(did, error = %e, "failed to resolve PDS endpoint, skipping DID");
            }
        }
    }

    let processed_repos = Arc::new(AtomicI32::new(0));
    let total_records = Arc::new(AtomicI32::new(0));

    let state = Arc::new(state);
    let collections = Arc::new(collections);
    let job_id_arc = Arc::new(job_id.clone());

    // Process PDSes with nested concurrency
    let pds_entries: Vec<(String, Vec<String>)> = pds_to_dids.into_iter().collect();

    stream::iter(pds_entries)
        .for_each_concurrent(10, |(pds_endpoint, dids)| {
            let state = Arc::clone(&state);
            let collections = Arc::clone(&collections);
            let processed_repos = Arc::clone(&processed_repos);
            let total_records = Arc::clone(&total_records);
            let job_id = Arc::clone(&job_id_arc);

            async move {
                stream::iter(dids)
                    .for_each_concurrent(3, |did| {
                        let state = Arc::clone(&state);
                        let collections = Arc::clone(&collections);
                        let processed_repos = Arc::clone(&processed_repos);
                        let total_records = Arc::clone(&total_records);
                        let pds_endpoint = pds_endpoint.clone();
                        let job_id = Arc::clone(&job_id);

                        async move {
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

                            let repos = processed_repos.fetch_add(1, Ordering::Relaxed) + 1;

                            // Update DB progress every 100 repos
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
                            }
                        }
                    })
                    .await;
            }
        })
        .await;

    let final_processed = processed_repos.load(Ordering::Relaxed);
    let final_records = total_records.load(Ordering::Relaxed);

    complete_job(&state, &job_id, final_processed, final_records, None).await;

    log_event(
        &state.db,
        EventLog {
            event_type: "backfill.completed".to_string(),
            severity: Severity::Info,
            actor_did: None,
            subject: body.collection.clone(),
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
// Helper functions
// ---------------------------------------------------------------------------

async fn fail_job(state: &AppState, job_id: &str, error: &str) {
    let now = now_rfc3339();
    let backend = state.db_backend;
    let sql = adapt_sql(
        "UPDATE backfill_jobs SET status = 'failed', completed_at = ?, error = ? WHERE id = ?",
        backend,
    );
    let _ = sqlx::query(&sql)
        .bind(&now)
        .bind(error)
        .bind(job_id)
        .execute(&state.db)
        .await;
}

async fn complete_job(
    state: &AppState,
    job_id: &str,
    processed_repos: i32,
    total_records: i32,
    error: Option<&str>,
) {
    let now = now_rfc3339();
    let backend = state.db_backend;

    let sql = adapt_sql(
        "UPDATE backfill_jobs SET status = 'completed', completed_at = ?, processed_repos = ?, total_records = ?, error = ? WHERE id = ?",
        backend,
    );
    let _ = sqlx::query(&sql)
        .bind(&now)
        .bind(processed_repos)
        .bind(total_records)
        .bind(error)
        .bind(job_id)
        .execute(&state.db)
        .await;
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
