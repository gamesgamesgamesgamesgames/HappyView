use axum::Json;
use axum::extract::State;

use crate::AppState;
use crate::error::AppError;

use super::auth::AdminAuth;
use super::types::{CollectionStat, StatsResponse};

/// GET /admin/stats — system statistics.
pub(super) async fn stats(
    State(state): State<AppState>,
    _admin: AdminAuth,
) -> Result<Json<StatsResponse>, AppError> {
    let total: (i64,) = sqlx::query_as("SELECT COUNT(*) FROM records")
        .fetch_one(&state.db)
        .await
        .map_err(|e| AppError::Internal(format!("failed to count records: {e}")))?;

    let collections: Vec<(String, i64)> = sqlx::query_as(
        r#"
        SELECT c.collection, COALESCE(r.cnt, 0) AS count
        FROM (
            SELECT id AS collection FROM lexicons
            WHERE lexicon_json->'defs'->'main'->>'type' = 'record'
        ) c
        LEFT JOIN (
            SELECT collection, COUNT(*) AS cnt FROM records GROUP BY collection
        ) r ON r.collection = c.collection
        ORDER BY c.collection
        "#,
    )
    .fetch_all(&state.db)
    .await
    .map_err(|e| AppError::Internal(format!("failed to count by collection: {e}")))?;

    Ok(Json(StatsResponse {
        total_records: total.0,
        collections: collections
            .into_iter()
            .map(|(collection, count)| CollectionStat { collection, count })
            .collect(),
    }))
}
