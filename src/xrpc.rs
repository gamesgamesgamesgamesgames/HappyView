use axum::extract::{Path, Query, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::Json;
use serde_json::{json, Value};
use std::collections::{HashMap, HashSet};

use crate::auth::Claims;
use crate::error::AppError;
use crate::lexicon::LexiconType;
use crate::profile;
use crate::repo;
use crate::AppState;

// ---------------------------------------------------------------------------
// Catch-all handler
// ---------------------------------------------------------------------------

/// Catch-all GET handler for XRPC queries.
pub async fn xrpc_get(
    State(state): State<AppState>,
    Path(method): Path<String>,
    Query(params): Query<HashMap<String, String>>,
) -> Result<Response, AppError> {
    let lexicon = state
        .lexicons
        .get(&method)
        .await
        .ok_or_else(|| AppError::BadRequest(format!("method not found: {method}")))?;

    if lexicon.lexicon_type != LexiconType::Query {
        return Err(AppError::BadRequest(format!(
            "{method} is not a query endpoint"
        )));
    }

    handle_query(&state, &method, &params, &lexicon).await
}

/// Catch-all POST handler for XRPC procedures.
pub async fn xrpc_post(
    State(state): State<AppState>,
    Path(method): Path<String>,
    claims: Claims,
    Json(body): Json<Value>,
) -> Result<Response, AppError> {
    let lexicon = state
        .lexicons
        .get(&method)
        .await
        .ok_or_else(|| AppError::BadRequest(format!("method not found: {method}")))?;

    if lexicon.lexicon_type != LexiconType::Procedure {
        return Err(AppError::BadRequest(format!(
            "{method} is not a procedure endpoint"
        )));
    }

    handle_procedure(&state, &method, &claims, &body, &lexicon).await
}

// ---------------------------------------------------------------------------
// Generic query handler
// ---------------------------------------------------------------------------

async fn handle_query(
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
    let collection = lexicon
        .target_collection
        .as_deref()
        .ok_or_else(|| {
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
        if let Ok(pds) = profile::resolve_pds_endpoint(&state.http, did).await {
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

async fn handle_get_record(state: &AppState, uri: &str) -> Result<Response, AppError> {
    let did = repo::parse_did_from_at_uri(uri)?;

    let row: Option<(Value,)> =
        sqlx::query_as("SELECT record FROM records WHERE uri = $1")
            .bind(uri)
            .fetch_optional(&state.db)
            .await
            .map_err(|e| AppError::Internal(format!("DB query failed: {e}")))?;

    let (mut record,) =
        row.ok_or_else(|| AppError::NotFound("record not found".into()))?;

    let pds = profile::resolve_pds_endpoint(&state.http, &did).await?;
    repo::enrich_media_blobs(&mut record, &pds, &did);

    record
        .as_object_mut()
        .map(|obj| obj.insert("uri".to_string(), json!(uri)));

    Ok(Json(json!({ "record": record })).into_response())
}

// ---------------------------------------------------------------------------
// Generic procedure handler
// ---------------------------------------------------------------------------

async fn handle_procedure(
    state: &AppState,
    method: &str,
    claims: &Claims,
    input: &Value,
    lexicon: &crate::lexicon::ParsedLexicon,
) -> Result<Response, AppError> {
    let collection = lexicon
        .target_collection
        .as_deref()
        .ok_or_else(|| {
            AppError::BadRequest(format!(
                "{method} has no target_collection configured"
            ))
        })?;

    let session = repo::get_atp_session(state, claims.token()).await?;

    // Determine create vs put based on whether input has a `uri` field.
    let has_uri = input.get("uri").and_then(|v| v.as_str()).is_some();

    if has_uri {
        handle_put_record(state, claims, input, collection, &session).await
    } else {
        handle_create_record(state, claims, input, collection, &session).await
    }
}

async fn handle_create_record(
    state: &AppState,
    claims: &Claims,
    input: &Value,
    collection: &str,
    session: &repo::AtpSession,
) -> Result<Response, AppError> {
    // Build record from input, adding $type
    let mut record = input.clone();
    if let Some(obj) = record.as_object_mut() {
        obj.insert("$type".to_string(), json!(collection));
        // Remove fields that are procedure params, not record fields
        obj.remove("shouldPublish");
    }

    let pds_body = json!({
        "repo": claims.did(),
        "collection": collection,
        "record": record,
    });

    let resp = repo::pds_post_json_raw(state, session, "com.atproto.repo.createRecord", &pds_body).await?;

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
            let rkey = uri.split('/').last().unwrap_or_default();
            let _ = sqlx::query(
                r#"
                INSERT INTO records (uri, did, collection, rkey, record, cid)
                VALUES ($1, $2, $3, $4, $5, $6)
                ON CONFLICT (uri) DO UPDATE
                    SET record = EXCLUDED.record,
                        cid = EXCLUDED.cid
                "#,
            )
            .bind(uri)
            .bind(claims.did())
            .bind(collection)
            .bind(rkey)
            .bind(&record)
            .bind(cid)
            .execute(&state.db)
            .await;
        }

        Ok((
            StatusCode::OK,
            [(axum::http::header::CONTENT_TYPE, "application/json")],
            bytes,
        )
            .into_response())
    } else {
        repo::forward_pds_response(resp).await
    }
}

async fn handle_put_record(
    state: &AppState,
    claims: &Claims,
    input: &Value,
    collection: &str,
    session: &repo::AtpSession,
) -> Result<Response, AppError> {
    let uri = input
        .get("uri")
        .and_then(|v| v.as_str())
        .ok_or_else(|| AppError::BadRequest("missing uri field".into()))?;

    let rkey = uri
        .split('/')
        .last()
        .ok_or_else(|| AppError::Internal("invalid AT URI".into()))?;

    // Build record from input, adding $type
    let mut record = input.clone();
    if let Some(obj) = record.as_object_mut() {
        obj.insert("$type".to_string(), json!(collection));
        obj.remove("uri");
        obj.remove("shouldPublish");
    }

    let pds_body = json!({
        "repo": claims.did(),
        "collection": collection,
        "rkey": rkey,
        "record": record,
    });

    let resp = repo::pds_post_json_raw(state, session, "com.atproto.repo.putRecord", &pds_body).await?;

    if resp.status().is_success() {
        let bytes = resp
            .bytes()
            .await
            .map_err(|e| AppError::Internal(format!("failed to read PDS response: {e}")))?;

        let pds_result: Value = serde_json::from_slice(&bytes)
            .map_err(|e| AppError::Internal(format!("invalid PDS JSON: {e}")))?;

        let cid = pds_result
            .get("cid")
            .and_then(|v| v.as_str())
            .unwrap_or_default();

        let _ = sqlx::query(
            r#"
            INSERT INTO records (uri, did, collection, rkey, record, cid)
            VALUES ($1, $2, $3, $4, $5, $6)
            ON CONFLICT (uri) DO UPDATE
                SET record = EXCLUDED.record,
                    cid = EXCLUDED.cid,
                    indexed_at = NOW()
            "#,
        )
        .bind(uri)
        .bind(claims.did())
        .bind(collection)
        .bind(rkey)
        .bind(&record)
        .bind(cid)
        .execute(&state.db)
        .await;

        Ok((
            StatusCode::OK,
            [(axum::http::header::CONTENT_TYPE, "application/json")],
            bytes,
        )
            .into_response())
    } else {
        repo::forward_pds_response(resp).await
    }
}
