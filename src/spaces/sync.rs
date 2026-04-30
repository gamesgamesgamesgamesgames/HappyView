use uuid::Uuid;

use crate::db::DatabaseBackend;
use crate::db::now_rfc3339;
use crate::error::AppError;
use crate::profile::resolve_pds_endpoint;
use crate::spaces::types::*;
use crate::spaces::{db, members};

/// Sync all members of a space by pulling records from their PDSes.
pub async fn sync_space(
    http: &reqwest::Client,
    pool: &sqlx::AnyPool,
    backend: DatabaseBackend,
    plc_url: &str,
    space_id: &str,
    collections: &[String],
) -> Result<SyncSpaceResult, AppError> {
    let resolved = members::resolve_members(pool, backend, space_id).await?;
    let mut results = Vec::new();

    for member in &resolved {
        let result = sync_member(
            http,
            pool,
            backend,
            plc_url,
            space_id,
            &member.did,
            collections,
        )
        .await;

        results.push(MemberSyncResult {
            did: member.did.clone(),
            records_synced: result.as_ref().map(|r| r.records_synced).unwrap_or(0),
            error: result.err().map(|e| e.to_string()),
        });
    }

    let total = results.iter().map(|r| r.records_synced).sum();

    Ok(SyncSpaceResult {
        members_processed: results.len(),
        total_records_synced: total,
        member_results: results,
    })
}

/// Sync records from a single member's PDS for a given space.
pub async fn sync_member(
    http: &reqwest::Client,
    pool: &sqlx::AnyPool,
    backend: DatabaseBackend,
    plc_url: &str,
    space_id: &str,
    member_did: &str,
    collections: &[String],
) -> Result<MemberSyncSummary, AppError> {
    let state_id = match db::get_sync_state(pool, backend, space_id, member_did).await? {
        Some(s) => s.id,
        None => {
            let id = Uuid::new_v4().to_string();
            let initial = SpaceSyncState {
                id: id.clone(),
                space_id: space_id.to_string(),
                member_did: member_did.to_string(),
                cursor: None,
                last_synced_at: None,
                status: SyncStatus::Pending,
                error: None,
            };
            db::upsert_sync_state(pool, backend, &initial).await?;
            id
        }
    };

    // Mark as syncing
    let syncing_state = SpaceSyncState {
        id: state_id.clone(),
        space_id: space_id.to_string(),
        member_did: member_did.to_string(),
        cursor: None,
        last_synced_at: None,
        status: SyncStatus::Syncing,
        error: None,
    };
    db::upsert_sync_state(pool, backend, &syncing_state).await?;

    let result = pull_member_records(
        http,
        pool,
        backend,
        plc_url,
        space_id,
        member_did,
        collections,
    )
    .await;

    match result {
        Ok(summary) => {
            let done = SpaceSyncState {
                id: state_id,
                space_id: space_id.to_string(),
                member_did: member_did.to_string(),
                cursor: summary.cursor.clone(),
                last_synced_at: Some(now_rfc3339()),
                status: SyncStatus::Synced,
                error: None,
            };
            db::upsert_sync_state(pool, backend, &done).await?;
            Ok(summary)
        }
        Err(e) => {
            let err_state = SpaceSyncState {
                id: state_id,
                space_id: space_id.to_string(),
                member_did: member_did.to_string(),
                cursor: None,
                last_synced_at: Some(now_rfc3339()),
                status: SyncStatus::Error,
                error: Some(e.to_string()),
            };
            db::upsert_sync_state(pool, backend, &err_state).await?;
            Err(e)
        }
    }
}

async fn pull_member_records(
    http: &reqwest::Client,
    pool: &sqlx::AnyPool,
    backend: DatabaseBackend,
    plc_url: &str,
    space_id: &str,
    member_did: &str,
    collections: &[String],
) -> Result<MemberSyncSummary, AppError> {
    let pds_url = resolve_pds_endpoint(http, plc_url, member_did).await?;
    let mut total_records = 0usize;
    let mut last_cursor = None;

    for collection in collections {
        let mut cursor: Option<String> = None;
        loop {
            let (records, next_cursor) = fetch_records_page(
                http,
                &pds_url,
                member_did,
                collection,
                cursor.as_deref(),
                100,
            )
            .await?;

            if records.is_empty() {
                break;
            }

            for record in &records {
                let uri = record["uri"].as_str().unwrap_or("");
                let rkey = extract_rkey(uri);
                let cid = record["cid"].as_str().unwrap_or("").to_string();
                let value = record
                    .get("value")
                    .cloned()
                    .unwrap_or(serde_json::Value::Null);

                let space_record_uri = format!("ats://{space_id}/{member_did}/{collection}/{rkey}");

                let space_record = SpaceRecord {
                    uri: space_record_uri,
                    space_id: space_id.to_string(),
                    author_did: member_did.to_string(),
                    collection: collection.clone(),
                    rkey: rkey.to_string(),
                    record: value,
                    cid,
                    indexed_at: now_rfc3339(),
                };

                db::upsert_space_record(pool, backend, &space_record).await?;
                total_records += 1;
            }

            last_cursor = next_cursor.clone();
            cursor = next_cursor;

            if cursor.is_none() {
                break;
            }
        }
    }

    Ok(MemberSyncSummary {
        records_synced: total_records,
        cursor: last_cursor,
    })
}

async fn fetch_records_page(
    http: &reqwest::Client,
    pds_url: &str,
    repo: &str,
    collection: &str,
    cursor: Option<&str>,
    limit: u32,
) -> Result<(Vec<serde_json::Value>, Option<String>), AppError> {
    let mut url = format!(
        "{}/xrpc/com.atproto.repo.listRecords?repo={}&collection={}&limit={}",
        pds_url.trim_end_matches('/'),
        repo,
        collection,
        limit,
    );

    if let Some(c) = cursor {
        url.push_str(&format!("&cursor={c}"));
    }

    let resp = http
        .get(&url)
        .send()
        .await
        .map_err(|e| AppError::Internal(format!("PDS request failed: {e}")))?;

    if !resp.status().is_success() {
        let status = resp.status();
        return Err(AppError::Internal(format!(
            "PDS listRecords failed with {status} for {repo}/{collection}"
        )));
    }

    let body: serde_json::Value = resp
        .json()
        .await
        .map_err(|e| AppError::Internal(format!("invalid PDS response: {e}")))?;

    let records = body["records"].as_array().cloned().unwrap_or_default();

    let next_cursor = body["cursor"].as_str().map(|s| s.to_string());

    Ok((records, next_cursor))
}

fn extract_rkey(uri: &str) -> &str {
    uri.rsplit('/').next().unwrap_or("")
}

// ---------------------------------------------------------------------------
// Result types
// ---------------------------------------------------------------------------

pub struct SyncSpaceResult {
    pub members_processed: usize,
    pub total_records_synced: usize,
    pub member_results: Vec<MemberSyncResult>,
}

pub struct MemberSyncResult {
    pub did: String,
    pub records_synced: usize,
    pub error: Option<String>,
}

pub struct MemberSyncSummary {
    pub records_synced: usize,
    pub cursor: Option<String>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn extract_rkey_from_at_uri() {
        assert_eq!(
            extract_rkey("at://did:plc:abc/app.bsky.feed.post/3k2abc"),
            "3k2abc"
        );
    }

    #[test]
    fn extract_rkey_from_empty() {
        assert_eq!(extract_rkey(""), "");
    }

    #[test]
    fn extract_rkey_no_slash() {
        assert_eq!(extract_rkey("singlevalue"), "singlevalue");
    }
}
