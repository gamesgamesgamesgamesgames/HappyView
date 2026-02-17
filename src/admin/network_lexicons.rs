use axum::Json;
use axum::extract::{Path, State};
use axum::http::StatusCode;
use serde_json::Value;

use crate::AppState;
use crate::error::AppError;
use crate::lexicon::{LexiconType, ParsedLexicon, ProcedureAction};
use crate::resolve::{fetch_lexicon_from_pds, resolve_nsid_authority};

use super::auth::AdminAuth;
use super::types::{AddNetworkLexiconBody, NetworkLexiconSummary};

/// Send the current record collection list to the Tap task so it
/// syncs the updated filter.
async fn notify_collections(state: &AppState) {
    let collections = state.lexicons.get_record_collections().await;
    let _ = state.collections_tx.send(collections);
}

/// POST /admin/network-lexicons — add a network lexicon to watch.
pub(super) async fn add(
    State(state): State<AppState>,
    _admin: AdminAuth,
    Json(body): Json<AddNetworkLexiconBody>,
) -> Result<(StatusCode, Json<Value>), AppError> {
    let nsid = &body.nsid;

    // Resolve NSID authority via DNS TXT lookup.
    let (authority_did, pds_endpoint) =
        resolve_nsid_authority(&state.http, &state.config.plc_url, nsid).await?;

    // Fetch the lexicon from the authority's PDS.
    let lexicon_json =
        fetch_lexicon_from_pds(&state.http, &pds_endpoint, &authority_did, nsid).await?;

    // Parse to validate.
    let parsed = ParsedLexicon::parse(
        lexicon_json.clone(),
        1,
        body.target_collection.clone(),
        ProcedureAction::Upsert,
    )
    .map_err(|e| AppError::BadRequest(format!("failed to parse lexicon: {e}")))?;

    // Upsert into lexicons table with network source.
    let row: (i32,) = sqlx::query_as(
        r#"
        INSERT INTO lexicons (id, lexicon_json, backfill, target_collection, source, authority_did, last_fetched_at)
        VALUES ($1, $2, false, $3, 'network', $4, NOW())
        ON CONFLICT (id) DO UPDATE SET
            lexicon_json = EXCLUDED.lexicon_json,
            target_collection = EXCLUDED.target_collection,
            source = 'network',
            authority_did = EXCLUDED.authority_did,
            last_fetched_at = NOW(),
            revision = lexicons.revision + 1,
            updated_at = NOW()
        RETURNING revision
        "#,
    )
    .bind(nsid)
    .bind(&lexicon_json)
    .bind(&body.target_collection)
    .bind(&authority_did)
    .fetch_one(&state.db)
    .await
    .map_err(|e| AppError::Internal(format!("failed to upsert network lexicon: {e}")))?;

    let revision = row.0;

    // Update in-memory registry.
    let is_record = parsed.lexicon_type == LexiconType::Record;
    let parsed = ParsedLexicon::parse(
        lexicon_json,
        revision,
        body.target_collection,
        ProcedureAction::Upsert,
    )
    .map_err(|e| AppError::Internal(format!("failed to re-parse lexicon: {e}")))?;
    state.lexicons.upsert(parsed).await;

    if is_record {
        notify_collections(&state).await;
    }

    Ok((
        StatusCode::CREATED,
        Json(serde_json::json!({
            "nsid": nsid,
            "authority_did": authority_did,
            "revision": revision,
        })),
    ))
}

/// GET /admin/network-lexicons — list tracked network lexicons.
pub(super) async fn list(
    State(state): State<AppState>,
    _admin: AdminAuth,
) -> Result<Json<Vec<NetworkLexiconSummary>>, AppError> {
    #[allow(clippy::type_complexity)]
    let rows: Vec<(String, Option<String>, Option<String>, Option<chrono::DateTime<chrono::Utc>>, chrono::DateTime<chrono::Utc>)> =
        sqlx::query_as(
            "SELECT id, authority_did, target_collection, last_fetched_at, created_at FROM lexicons WHERE source = 'network' ORDER BY id",
        )
        .fetch_all(&state.db)
        .await
        .map_err(|e| AppError::Internal(format!("failed to list network lexicons: {e}")))?;

    let summaries: Vec<NetworkLexiconSummary> = rows
        .into_iter()
        .map(
            |(nsid, authority_did, target_collection, last_fetched_at, created_at)| {
                NetworkLexiconSummary {
                    nsid,
                    authority_did: authority_did.unwrap_or_default(),
                    target_collection,
                    last_fetched_at,
                    created_at,
                }
            },
        )
        .collect();

    Ok(Json(summaries))
}

/// DELETE /admin/network-lexicons/{nsid} — stop watching a network lexicon.
pub(super) async fn remove(
    State(state): State<AppState>,
    _admin: AdminAuth,
    Path(nsid): Path<String>,
) -> Result<StatusCode, AppError> {
    let result = sqlx::query("DELETE FROM lexicons WHERE id = $1 AND source = 'network'")
        .bind(&nsid)
        .execute(&state.db)
        .await
        .map_err(|e| AppError::Internal(format!("failed to delete network lexicon: {e}")))?;

    if result.rows_affected() == 0 {
        return Err(AppError::NotFound(format!(
            "network lexicon '{nsid}' not found"
        )));
    }

    state.lexicons.remove(&nsid).await;
    notify_collections(&state).await;

    Ok(StatusCode::NO_CONTENT)
}
