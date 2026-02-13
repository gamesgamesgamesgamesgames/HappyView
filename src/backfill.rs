use serde::Deserialize;
use serde_json::Value;
use sqlx::PgPool;
use std::sync::Arc;
use tokio::sync::Semaphore;
use tracing::{debug, error, info, warn};

use crate::profile;

// ---------------------------------------------------------------------------
// Relay / PDS response types
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
    value: Value,
}

// ---------------------------------------------------------------------------
// Relay discovery
// ---------------------------------------------------------------------------

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

/// Fetch all records for a DID + collection from their PDS via
/// `com.atproto.repo.listRecords`. Paginates until done.
async fn fetch_records(
    http: &reqwest::Client,
    pds_url: &str,
    did: &str,
    collection: &str,
) -> Result<Vec<(String, String, String, Value)>, String> {
    let base = pds_url.trim_end_matches('/');
    let mut records = Vec::new();
    let mut cursor: Option<String> = None;

    loop {
        let mut url = format!(
            "{base}/xrpc/com.atproto.repo.listRecords?repo={did}&collection={collection}&limit=100"
        );
        if let Some(ref c) = cursor {
            url.push_str(&format!("&cursor={c}"));
        }

        let resp = http
            .get(&url)
            .send()
            .await
            .map_err(|e| format!("PDS listRecords failed: {e}"))?;

        if !resp.status().is_success() {
            return Err(format!("PDS returned {} for {did}", resp.status()));
        }

        let body: ListRecordsResponse = resp
            .json()
            .await
            .map_err(|e| format!("invalid PDS listRecords response: {e}"))?;

        let page_count = body.records.len();
        for entry in body.records {
            let rkey = entry.uri.split('/').last().unwrap_or_default().to_string();
            records.push((entry.uri, rkey, entry.cid, entry.value));
        }

        match body.cursor {
            Some(c) if page_count > 0 => cursor = Some(c),
            _ => break,
        }
    }

    Ok(records)
}

// ---------------------------------------------------------------------------
// Job runner
// ---------------------------------------------------------------------------

/// Run a single backfill job: discover repos, fetch records, upsert into DB.
async fn run_job(
    db: &PgPool,
    http: &reqwest::Client,
    relay_url: &str,
    job_id: &str,
) -> Result<(), String> {
    // Fetch the job
    let job: (Option<String>, Option<String>) = sqlx::query_as(
        "SELECT collection, did FROM backfill_jobs WHERE id::text = $1",
    )
    .bind(job_id)
    .fetch_one(db)
    .await
    .map_err(|e| format!("failed to fetch job: {e}"))?;

    let (job_collection, job_did) = job;

    // Mark as running
    let _ = sqlx::query(
        "UPDATE backfill_jobs SET status = 'running', started_at = NOW() WHERE id::text = $1",
    )
    .bind(job_id)
    .execute(db)
    .await;

    // Determine target collections
    let collections: Vec<String> = if let Some(ref col) = job_collection {
        vec![col.clone()]
    } else {
        // All backfill-eligible collections
        let rows: Vec<(String,)> = sqlx::query_as(
            "SELECT id FROM lexicons WHERE backfill = TRUE AND lexicon_json->'defs'->'main'->>'type' = 'record'",
        )
        .fetch_all(db)
        .await
        .map_err(|e| format!("failed to query backfill-eligible lexicons: {e}"))?;
        rows.into_iter().map(|(id,)| id).collect()
    };

    if collections.is_empty() {
        let _ = sqlx::query(
            "UPDATE backfill_jobs SET status = 'completed', completed_at = NOW(), error = 'no backfill-eligible collections' WHERE id::text = $1",
        )
        .bind(job_id)
        .execute(db)
        .await;
        return Ok(());
    }

    info!(job = job_id, ?collections, "starting backfill");

    let semaphore = Arc::new(Semaphore::new(8));
    let mut total_repos = 0i32;
    let mut processed_repos = 0i32;
    let mut total_records = 0i32;

    for collection in &collections {
        // Discover DIDs
        let dids = if let Some(ref did) = job_did {
            vec![did.clone()]
        } else {
            match list_repos_by_collection(http, relay_url, collection).await {
                Ok(dids) => dids,
                Err(e) => {
                    warn!(collection, error = %e, "failed to discover repos, skipping");
                    continue;
                }
            }
        };

        total_repos += dids.len() as i32;
        let _ = sqlx::query("UPDATE backfill_jobs SET total_repos = $2 WHERE id::text = $1")
            .bind(job_id)
            .bind(total_repos)
            .execute(db)
            .await;

        // Process each DID concurrently (bounded by semaphore)
        let mut tasks = Vec::new();

        for did in dids {
            let permit = semaphore.clone().acquire_owned().await.unwrap();
            let http = http.clone();
            let db = db.clone();
            let collection = collection.clone();

            let task = tokio::spawn(async move {
                let _permit = permit;
                backfill_repo(&db, &http, &did, &collection).await
            });
            tasks.push(task);
        }

        for task in tasks {
            match task.await {
                Ok(Ok(count)) => {
                    total_records += count;
                    processed_repos += 1;
                }
                Ok(Err(e)) => {
                    warn!(error = %e, "repo backfill failed");
                    processed_repos += 1;
                }
                Err(e) => {
                    warn!(error = %e, "repo backfill task panicked");
                    processed_repos += 1;
                }
            }

            // Update progress periodically
            let _ = sqlx::query(
                "UPDATE backfill_jobs SET processed_repos = $2, total_records = $3 WHERE id::text = $1",
            )
            .bind(job_id)
            .bind(processed_repos)
            .bind(total_records)
            .execute(db)
            .await;
        }
    }

    // Mark completed
    let _ = sqlx::query(
        "UPDATE backfill_jobs SET status = 'completed', completed_at = NOW(), processed_repos = $2, total_records = $3 WHERE id::text = $1",
    )
    .bind(job_id)
    .bind(processed_repos)
    .bind(total_records)
    .execute(db)
    .await;

    info!(job = job_id, processed_repos, total_records, "backfill completed");
    Ok(())
}

/// Backfill a single repo's records for a collection. Returns the number of
/// records upserted.
async fn backfill_repo(
    db: &PgPool,
    http: &reqwest::Client,
    did: &str,
    collection: &str,
) -> Result<i32, String> {
    // Resolve PDS
    let pds = profile::resolve_pds_endpoint(http, did)
        .await
        .map_err(|e| format!("PDS resolution failed for {did}: {e}"))?;

    // Fetch records
    let records = fetch_records(http, &pds, did, collection).await?;
    let count = records.len() as i32;

    debug!(did, collection, count, "fetched records from PDS");

    // Upsert into DB
    for (uri, rkey, cid, value) in records {
        let _ = sqlx::query(
            r#"
            INSERT INTO records (uri, did, collection, rkey, record, cid)
            VALUES ($1, $2, $3, $4, $5, $6)
            ON CONFLICT (uri) DO UPDATE
                SET record = EXCLUDED.record,
                    cid = EXCLUDED.cid
            "#,
        )
        .bind(&uri)
        .bind(did)
        .bind(collection)
        .bind(&rkey)
        .bind(&value)
        .bind(&cid)
        .execute(db)
        .await
        .map_err(|e| format!("DB upsert failed for {uri}: {e}"))?;
    }

    Ok(count)
}

// ---------------------------------------------------------------------------
// Background worker
// ---------------------------------------------------------------------------

/// Spawn a background task that polls for pending backfill jobs and runs them.
pub fn spawn_worker(db: PgPool, http: reqwest::Client, relay_url: String) {
    tokio::spawn(async move {
        info!("backfill worker started");
        loop {
            // Poll for a pending job
            let job: Option<(String,)> = sqlx::query_as(
                "SELECT id::text FROM backfill_jobs WHERE status = 'pending' ORDER BY created_at ASC LIMIT 1",
            )
            .fetch_optional(&db)
            .await
            .unwrap_or(None);

            if let Some((job_id,)) = job {
                info!(job = %job_id, "picked up backfill job");
                if let Err(e) = run_job(&db, &http, &relay_url, &job_id).await {
                    error!(job = %job_id, error = %e, "backfill job failed");
                    let _ = sqlx::query(
                        "UPDATE backfill_jobs SET status = 'failed', completed_at = NOW(), error = $2 WHERE id::text = $1",
                    )
                    .bind(&job_id)
                    .bind(&e)
                    .execute(&db)
                    .await;
                }
            } else {
                // No pending jobs, wait before polling again
                tokio::time::sleep(std::time::Duration::from_secs(5)).await;
            }
        }
    });
}
