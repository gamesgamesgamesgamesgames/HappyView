use axum::Json;
use axum::response::{IntoResponse, Response};
use serde_json::{Value, json};
use std::collections::{HashMap, HashSet};

use crate::AppState;
use crate::error::AppError;
use crate::profile;
use crate::repo;

pub(super) async fn handle_query(
    state: &AppState,
    method: &str,
    params: &HashMap<String, String>,
    lexicon: &crate::lexicon::ParsedLexicon,
) -> Result<Response, AppError> {
    // Single-record query: has a `uri` parameter
    if let Some(uri) = params.get("uri") {
        return handle_get_record(state, uri).await;
    }

    // List query: needs a target collection to know what to query
    let collection = lexicon.target_collection.as_deref().ok_or_else(|| {
        AppError::BadRequest(format!(
            "{method} has no target_collection configured for list queries"
        ))
    })?;

    let limit: i64 = params
        .get("limit")
        .and_then(|l| l.parse().ok())
        .unwrap_or(20)
        .min(100);

    let offset: i64 = params
        .get("cursor")
        .and_then(|c| c.parse().ok())
        .unwrap_or(0);

    let did = params.get("did");

    let rows: Vec<(String, String, Value)> = if let Some(did) = did {
        sqlx::query_as(
            "SELECT uri, did, record FROM records WHERE collection = $1 AND did = $2 ORDER BY indexed_at DESC LIMIT $3 OFFSET $4",
        )
        .bind(collection)
        .bind(did)
        .bind(limit)
        .bind(offset)
        .fetch_all(&state.db)
        .await
        .map_err(|e| AppError::Internal(format!("DB query failed: {e}")))?
    } else {
        sqlx::query_as(
            "SELECT uri, did, record FROM records WHERE collection = $1 ORDER BY indexed_at DESC LIMIT $2 OFFSET $3",
        )
        .bind(collection)
        .bind(limit)
        .bind(offset)
        .fetch_all(&state.db)
        .await
        .map_err(|e| AppError::Internal(format!("DB query failed: {e}")))?
    };

    let has_next_page = rows.len() as i64 == limit;

    // Resolve PDS endpoints for blob URL enrichment.
    let unique_dids: HashSet<&str> = rows.iter().map(|(_, did, _)| did.as_str()).collect();
    let mut pds_map: HashMap<String, String> = HashMap::new();
    for did in unique_dids {
        if let Ok(pds) =
            profile::resolve_pds_endpoint(&state.http, &state.config.plc_url, did).await
        {
            pds_map.insert(did.to_string(), pds);
        }
    }

    let records: Vec<Value> = rows
        .into_iter()
        .map(|(uri, did, mut record)| {
            if let Some(pds) = pds_map.get(&did) {
                repo::enrich_media_blobs(&mut record, pds, &did);
            }
            record
                .as_object_mut()
                .map(|obj| obj.insert("uri".to_string(), json!(uri)));
            record
        })
        .collect();

    let mut result = json!({ "records": records });
    if has_next_page {
        let next_cursor = (offset + limit).to_string();
        result
            .as_object_mut()
            .unwrap()
            .insert("cursor".to_string(), json!(next_cursor));
    }

    Ok(Json(result).into_response())
}

pub(super) async fn handle_get_record(state: &AppState, uri: &str) -> Result<Response, AppError> {
    let did = repo::parse_did_from_at_uri(uri)?;

    let row: Option<(Value,)> = sqlx::query_as("SELECT record FROM records WHERE uri = $1")
        .bind(uri)
        .fetch_optional(&state.db)
        .await
        .map_err(|e| AppError::Internal(format!("DB query failed: {e}")))?;

    let (mut record,) = row.ok_or_else(|| AppError::NotFound("record not found".into()))?;

    let pds = profile::resolve_pds_endpoint(&state.http, &state.config.plc_url, &did).await?;
    repo::enrich_media_blobs(&mut record, &pds, &did);

    record
        .as_object_mut()
        .map(|obj| obj.insert("uri".to_string(), json!(uri)));

    Ok(Json(json!({ "record": record })).into_response())
}
