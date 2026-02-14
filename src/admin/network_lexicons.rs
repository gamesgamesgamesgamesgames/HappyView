use axum::Json;
use axum::extract::{Path, State};
use axum::http::StatusCode;
use serde_json::Value;

use crate::AppState;
use crate::error::AppError;
use crate::lexicon::{LexiconType, ParsedLexicon};
use crate::resolve::{fetch_lexicon_from_pds, resolve_nsid_authority};

use super::auth::AdminAuth;
use super::types::{AddNetworkLexiconBody, NetworkLexiconSummary};

/// Send the current record collection list to the Jetstream task so it
/// reconnects with the updated filter.
async fn notify_jetstream(state: &AppState) {
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
    let parsed = ParsedLexicon::parse(lexicon_json.clone(), 1, body.target_collection.clone())
        .map_err(|e| AppError::BadRequest(format!("failed to parse lexicon: {e}")))?;

    // Insert into network_lexicons table.
    sqlx::query(
        r#"
        INSERT INTO network_lexicons (nsid, authority_did, target_collection, last_fetched_at)
        VALUES ($1, $2, $3, NOW())
        ON CONFLICT (nsid) DO UPDATE SET
            authority_did = EXCLUDED.authority_did,
            target_collection = EXCLUDED.target_collection,
            last_fetched_at = NOW()
        "#,
    )
    .bind(nsid)
    .bind(&authority_did)
    .bind(&body.target_collection)
    .execute(&state.db)
    .await
    .map_err(|e| AppError::Internal(format!("failed to insert network lexicon: {e}")))?;

    // Upsert into lexicons table.
    let row: (i32,) = sqlx::query_as(
        r#"
        INSERT INTO lexicons (id, lexicon_json, backfill, target_collection)
        VALUES ($1, $2, false, $3)
        ON CONFLICT (id) DO UPDATE SET
            lexicon_json = EXCLUDED.lexicon_json,
            target_collection = EXCLUDED.target_collection,
            revision = lexicons.revision + 1,
            updated_at = NOW()
        RETURNING revision
        "#,
    )
    .bind(nsid)
    .bind(&lexicon_json)
    .bind(&body.target_collection)
    .fetch_one(&state.db)
    .await
    .map_err(|e| AppError::Internal(format!("failed to upsert lexicon: {e}")))?;

    let revision = row.0;

    // Update in-memory registry.
    let is_record = parsed.lexicon_type == LexiconType::Record;
    let parsed = ParsedLexicon::parse(lexicon_json, revision, body.target_collection)
        .map_err(|e| AppError::Internal(format!("failed to re-parse lexicon: {e}")))?;
    state.lexicons.upsert(parsed).await;

    if is_record {
        notify_jetstream(&state).await;
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
    let rows: Vec<(String, String, Option<String>, Option<chrono::DateTime<chrono::Utc>>, chrono::DateTime<chrono::Utc>)> =
        sqlx::query_as(
            "SELECT nsid, authority_did, target_collection, last_fetched_at, created_at FROM network_lexicons ORDER BY nsid",
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
                    authority_did,
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
    let result = sqlx::query("DELETE FROM network_lexicons WHERE nsid = $1")
        .bind(&nsid)
        .execute(&state.db)
        .await
        .map_err(|e| AppError::Internal(format!("failed to delete network lexicon: {e}")))?;

    if result.rows_affected() == 0 {
        return Err(AppError::NotFound(format!(
            "network lexicon '{nsid}' not found"
        )));
    }

    // Also remove from lexicons table and registry.
    let _ = sqlx::query("DELETE FROM lexicons WHERE id = $1")
        .bind(&nsid)
        .execute(&state.db)
        .await;

    state.lexicons.remove(&nsid).await;
    notify_jetstream(&state).await;

    Ok(StatusCode::NO_CONTENT)
}
