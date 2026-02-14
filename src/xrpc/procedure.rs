use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use serde_json::{Value, json};

use crate::AppState;
use crate::auth::Claims;
use crate::error::AppError;
use crate::lexicon::ProcedureAction;
use crate::repo;

pub(super) async fn handle_procedure(
    state: &AppState,
    method: &str,
    claims: &Claims,
    input: &Value,
    lexicon: &crate::lexicon::ParsedLexicon,
) -> Result<Response, AppError> {
    let collection = lexicon.target_collection.as_deref().ok_or_else(|| {
        AppError::BadRequest(format!("{method} has no target_collection configured"))
    })?;

    let session = repo::get_atp_session(state, claims.token()).await?;

    match &lexicon.action {
        ProcedureAction::Create => {
            handle_create_record(state, claims, input, collection, &session).await
        }
        ProcedureAction::Update => {
            handle_put_record(state, claims, input, collection, &session).await
        }
        ProcedureAction::Delete => {
            handle_delete_record(state, claims, input, collection, &session).await
        }
        ProcedureAction::Upsert => {
            // Backwards-compatible: sniff for `uri` field to decide create vs put.
            let has_uri = input.get("uri").and_then(|v| v.as_str()).is_some();
            if has_uri {
                handle_put_record(state, claims, input, collection, &session).await
            } else {
                handle_create_record(state, claims, input, collection, &session).await
            }
        }
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

    let resp =
        repo::pds_post_json_raw(state, session, "com.atproto.repo.createRecord", &pds_body).await?;

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
            let rkey = uri.split('/').next_back().unwrap_or_default();
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
        .next_back()
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

    let resp =
        repo::pds_post_json_raw(state, session, "com.atproto.repo.putRecord", &pds_body).await?;

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

async fn handle_delete_record(
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
        .next_back()
        .ok_or_else(|| AppError::Internal("invalid AT URI".into()))?;

    let pds_body = json!({
        "repo": claims.did(),
        "collection": collection,
        "rkey": rkey,
    });

    let resp =
        repo::pds_post_json_raw(state, session, "com.atproto.repo.deleteRecord", &pds_body).await?;

    if resp.status().is_success() {
        let bytes = resp
            .bytes()
            .await
            .map_err(|e| AppError::Internal(format!("failed to read PDS response: {e}")))?;

        // Remove from local records table.
        let _ = sqlx::query("DELETE FROM records WHERE uri = $1")
            .bind(uri)
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
