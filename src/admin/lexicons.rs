use axum::Json;
use axum::extract::{Path, State};
use axum::http::StatusCode;
use serde_json::Value;

use crate::AppState;
use crate::error::AppError;
use crate::lexicon::{LexiconType, ParsedLexicon, ProcedureAction};

use super::auth::AdminAuth;
use super::types::{LexiconSummary, UploadLexiconBody};

/// Send the current record collection list to the Tap task so it
/// syncs the updated filter.
async fn notify_collections(state: &AppState) {
    let collections = state.lexicons.get_record_collections().await;
    let _ = state.collections_tx.send(collections);
}

/// POST /admin/lexicons — upload (upsert) a lexicon.
pub(super) async fn upload_lexicon(
    State(state): State<AppState>,
    _admin: AdminAuth,
    Json(body): Json<UploadLexiconBody>,
) -> Result<(StatusCode, Json<Value>), AppError> {
    // Validate basic structure
    let lexicon_version = body
        .lexicon_json
        .get("lexicon")
        .and_then(|v| v.as_i64())
        .ok_or_else(|| {
            AppError::BadRequest("lexicon JSON must have a numeric 'lexicon' field".into())
        })?;

    if lexicon_version != 1 {
        return Err(AppError::BadRequest(format!(
            "unsupported lexicon version: {lexicon_version}"
        )));
    }

    let id = body
        .lexicon_json
        .get("id")
        .and_then(|v| v.as_str())
        .ok_or_else(|| AppError::BadRequest("lexicon JSON must have a string 'id' field".into()))?
        .to_string();

    // Validate action
    let action =
        ProcedureAction::from_optional_str(body.action.as_deref()).map_err(AppError::BadRequest)?;

    // Validate it parses correctly
    ParsedLexicon::parse(
        body.lexicon_json.clone(),
        1,
        body.target_collection.clone(),
        action.clone(),
        body.script.clone(),
    )
    .map_err(|e| AppError::BadRequest(format!("failed to parse lexicon: {e}")))?;

    // Validate script if provided
    if let Some(ref script) = body.script {
        crate::lua::validate_script(script).map_err(AppError::BadRequest)?;
    }

    let action_str = action.to_optional_str();

    // Upsert into database
    let row: (i32,) = sqlx::query_as(
        r#"
        INSERT INTO lexicons (id, lexicon_json, backfill, target_collection, action, script, source)
        VALUES ($1, $2, $3, $4, $5, $6, 'manual')
        ON CONFLICT (id) DO UPDATE SET
            lexicon_json = EXCLUDED.lexicon_json,
            backfill = EXCLUDED.backfill,
            target_collection = EXCLUDED.target_collection,
            action = EXCLUDED.action,
            script = EXCLUDED.script,
            source = 'manual',
            revision = lexicons.revision + 1,
            updated_at = NOW()
        RETURNING revision
        "#,
    )
    .bind(&id)
    .bind(&body.lexicon_json)
    .bind(body.backfill)
    .bind(&body.target_collection)
    .bind(action_str)
    .bind(&body.script)
    .fetch_one(&state.db)
    .await
    .map_err(|e| AppError::Internal(format!("failed to upsert lexicon: {e}")))?;

    let revision = row.0;

    // Update in-memory registry with correct revision
    let parsed = ParsedLexicon::parse(
        body.lexicon_json,
        revision,
        body.target_collection,
        action,
        body.script,
    )
    .map_err(|e| AppError::Internal(format!("failed to re-parse lexicon: {e}")))?;
    let is_record = parsed.lexicon_type == LexiconType::Record;
    state.lexicons.upsert(parsed).await;

    if is_record {
        notify_collections(&state).await;
    }

    let status = if revision == 1 {
        StatusCode::CREATED
    } else {
        StatusCode::OK
    };

    Ok((
        status,
        Json(serde_json::json!({
            "id": id,
            "revision": revision,
        })),
    ))
}

/// GET /admin/lexicons — list all lexicons.
pub(super) async fn list_lexicons(
    State(state): State<AppState>,
    _admin: AdminAuth,
) -> Result<Json<Vec<LexiconSummary>>, AppError> {
    #[allow(clippy::type_complexity)]
    let rows: Vec<(String, i32, Value, bool, Option<String>, Option<String>, Option<String>, String, Option<String>, Option<chrono::DateTime<chrono::Utc>>, chrono::DateTime<chrono::Utc>, chrono::DateTime<chrono::Utc>)> =
        sqlx::query_as(
            "SELECT id, revision, lexicon_json, backfill, action, target_collection, script, source, authority_did, last_fetched_at, created_at, updated_at FROM lexicons ORDER BY id",
        )
        .fetch_all(&state.db)
        .await
        .map_err(|e| AppError::Internal(format!("failed to list lexicons: {e}")))?;

    let summaries: Vec<LexiconSummary> = rows
        .into_iter()
        .map(
            |(
                id,
                revision,
                json,
                backfill,
                action,
                target_collection,
                script,
                source,
                authority_did,
                last_fetched_at,
                created_at,
                updated_at,
            )| {
                let parsed =
                    ParsedLexicon::parse(json, revision, None, ProcedureAction::Upsert, None);
                let lexicon_type = parsed
                    .as_ref()
                    .map(|p| format!("{:?}", p.lexicon_type).to_lowercase())
                    .unwrap_or_else(|_| "unknown".into());
                let record_schema = parsed
                    .ok()
                    .filter(|p| p.lexicon_type == LexiconType::Record)
                    .and_then(|p| p.record_schema);

                LexiconSummary {
                    id,
                    revision,
                    lexicon_type,
                    backfill,
                    action,
                    target_collection,
                    has_script: script.is_some(),
                    source,
                    authority_did,
                    last_fetched_at,
                    created_at,
                    updated_at,
                    record_schema,
                }
            },
        )
        .collect();

    Ok(Json(summaries))
}

/// GET /admin/lexicons/:id — get a single lexicon.
pub(super) async fn get_lexicon(
    State(state): State<AppState>,
    _admin: AdminAuth,
    Path(id): Path<String>,
) -> Result<Json<Value>, AppError> {
    #[allow(clippy::type_complexity)]
    let row: Option<(String, i32, Value, bool, Option<String>, Option<String>, Option<String>, String, Option<String>, Option<chrono::DateTime<chrono::Utc>>, chrono::DateTime<chrono::Utc>, chrono::DateTime<chrono::Utc>)> =
        sqlx::query_as(
            "SELECT id, revision, lexicon_json, backfill, action, target_collection, script, source, authority_did, last_fetched_at, created_at, updated_at FROM lexicons WHERE id = $1",
        )
        .bind(&id)
        .fetch_optional(&state.db)
        .await
        .map_err(|e| AppError::Internal(format!("failed to get lexicon: {e}")))?;

    let (
        id,
        revision,
        lexicon_json,
        backfill,
        action,
        target_collection,
        script,
        source,
        authority_did,
        last_fetched_at,
        created_at,
        updated_at,
    ) = row.ok_or_else(|| AppError::NotFound(format!("lexicon '{id}' not found")))?;

    let lexicon_type = ParsedLexicon::parse(
        lexicon_json.clone(),
        revision,
        None,
        ProcedureAction::Upsert,
        None,
    )
    .map(|p| format!("{:?}", p.lexicon_type).to_lowercase())
    .unwrap_or_else(|_| "unknown".into());

    let has_script = script.is_some();

    Ok(Json(serde_json::json!({
        "id": id,
        "revision": revision,
        "lexicon_json": lexicon_json,
        "lexicon_type": lexicon_type,
        "backfill": backfill,
        "action": action,
        "target_collection": target_collection,
        "has_script": has_script,
        "script": script,
        "source": source,
        "authority_did": authority_did,
        "last_fetched_at": last_fetched_at,
        "created_at": created_at,
        "updated_at": updated_at,
    })))
}

/// DELETE /admin/lexicons/:id — remove a lexicon.
pub(super) async fn delete_lexicon(
    State(state): State<AppState>,
    _admin: AdminAuth,
    Path(id): Path<String>,
) -> Result<StatusCode, AppError> {
    let result = sqlx::query("DELETE FROM lexicons WHERE id = $1")
        .bind(&id)
        .execute(&state.db)
        .await
        .map_err(|e| AppError::Internal(format!("failed to delete lexicon: {e}")))?;

    if result.rows_affected() == 0 {
        return Err(AppError::NotFound(format!("lexicon '{id}' not found")));
    }

    state.lexicons.remove(&id).await;
    notify_collections(&state).await;

    Ok(StatusCode::NO_CONTENT)
}
