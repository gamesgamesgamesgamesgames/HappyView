//! Write sync records to user's PDS.

use serde_json::{Value, json};

use crate::AppState;
use crate::error::AppError;
use crate::plugin::sync::ProcessedRecord;
use crate::repo;

/// Result of writing a record to PDS
#[derive(Debug)]
#[allow(dead_code)]
pub struct WriteResult {
    pub uri: String,
    pub cid: String,
}

/// Write processed records to the user's PDS.
///
/// Returns the number of successfully written records.
pub async fn write_records_to_pds(
    state: &AppState,
    user_did: &str,
    records: Vec<ProcessedRecord>,
) -> Result<Vec<WriteResult>, AppError> {
    let session = repo::get_oauth_session(state, user_did).await?;

    let mut results = Vec::with_capacity(records.len());

    for record in records {
        // Generate rkey from dedup_key or create a timestamp-based one
        let rkey = record
            .dedup_key
            .as_ref()
            .map(|k| sanitize_rkey(k))
            .unwrap_or_else(generate_tid);

        // Build the putRecord request
        let body = json!({
            "repo": user_did,
            "collection": record.collection,
            "rkey": rkey,
            "record": record.record,
        });

        let resp =
            repo::pds_post_json_raw(state, &session, "com.atproto.repo.putRecord", &body).await?;

        if resp.status().is_success() {
            let bytes = resp
                .bytes()
                .await
                .map_err(|e| AppError::Internal(format!("failed to read PDS response: {e}")))?;

            let pds_result: Value = serde_json::from_slice(&bytes)
                .map_err(|e| AppError::Internal(format!("invalid PDS JSON: {e}")))?;

            if let (Some(uri), Some(cid)) = (
                pds_result.get("uri").and_then(|v| v.as_str()),
                pds_result.get("cid").and_then(|v| v.as_str()),
            ) {
                results.push(WriteResult {
                    uri: uri.to_string(),
                    cid: cid.to_string(),
                });
            }
        } else {
            let bytes = resp.bytes().await.unwrap_or_default();
            let body_str = String::from_utf8_lossy(&bytes);
            tracing::warn!(
                collection = %record.collection,
                rkey = %rkey,
                error = %body_str,
                "Failed to write record to PDS"
            );
            // Continue with other records even if one fails
        }
    }

    Ok(results)
}

/// Sanitize a dedup_key to be a valid rkey.
/// rkey must be 1-512 chars, alphanumeric plus .-_:~
fn sanitize_rkey(key: &str) -> String {
    let sanitized: String = key
        .chars()
        .filter(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '-' | '_' | ':' | '~'))
        .take(512)
        .collect();

    if sanitized.is_empty() {
        generate_tid()
    } else {
        sanitized
    }
}

/// Generate a TID (timestamp-based ID) for use as rkey.
fn generate_tid() -> String {
    use std::time::{SystemTime, UNIX_EPOCH};

    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_micros();

    // TID is base32-sortable encoding of microseconds since epoch
    // Using a simplified version here
    format!("{:0>13}", base32_encode(now as u64))
}

fn base32_encode(mut n: u64) -> String {
    const ALPHABET: &[u8] = b"234567abcdefghijklmnopqrstuvwxyz";
    let mut result = String::new();

    if n == 0 {
        return "2".to_string();
    }

    while n > 0 {
        result.insert(0, ALPHABET[(n % 32) as usize] as char);
        n /= 32;
    }

    result
}
