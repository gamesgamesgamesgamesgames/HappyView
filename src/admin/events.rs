use axum::{
    Json,
    extract::{Query, State},
};
use serde::{Deserialize, Serialize};
use serde_json::Value;

use super::auth::AdminAuth;
use crate::AppState;
use crate::error::AppError;

#[derive(Deserialize)]
pub struct EventsQuery {
    pub event_type: Option<String>,
    pub category: Option<String>,
    pub severity: Option<String>,
    pub subject: Option<String>,
    pub cursor: Option<String>,
    pub limit: Option<i64>,
}

#[derive(Serialize)]
pub struct EventResponse {
    pub id: String,
    pub event_type: String,
    pub severity: String,
    pub actor_did: Option<String>,
    pub subject: Option<String>,
    pub detail: Value,
    pub created_at: chrono::DateTime<chrono::Utc>,
}

#[derive(Serialize)]
pub struct EventsListResponse {
    pub events: Vec<EventResponse>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cursor: Option<String>,
}

/// GET /admin/events — list event logs with optional filters and pagination.
pub(super) async fn list_events(
    _auth: AdminAuth,
    State(state): State<AppState>,
    Query(query): Query<EventsQuery>,
) -> Result<Json<EventsListResponse>, AppError> {
    let limit = query.limit.unwrap_or(50).clamp(1, 100);

    let mut sql = String::from(
        "SELECT id::text, event_type, severity, actor_did, subject, detail, created_at
         FROM event_logs WHERE 1=1",
    );
    let mut param_count = 0u32;

    if query.event_type.is_some() {
        param_count += 1;
        sql.push_str(&format!(" AND event_type = ${param_count}"));
    }
    if query.category.is_some() {
        param_count += 1;
        sql.push_str(&format!(" AND event_type LIKE ${param_count}"));
    }
    if query.severity.is_some() {
        param_count += 1;
        sql.push_str(&format!(" AND severity = ${param_count}"));
    }
    if query.subject.is_some() {
        param_count += 1;
        sql.push_str(&format!(" AND subject = ${param_count}"));
    }
    if query.cursor.is_some() {
        param_count += 1;
        sql.push_str(&format!(" AND created_at < ${param_count}"));
    }

    param_count += 1;
    sql.push_str(&format!(" ORDER BY created_at DESC LIMIT ${param_count}"));

    #[allow(clippy::type_complexity)]
    let mut q = sqlx::query_as::<
        _,
        (
            String,
            String,
            String,
            Option<String>,
            Option<String>,
            Value,
            chrono::DateTime<chrono::Utc>,
        ),
    >(&sql);

    if let Some(ref event_type) = query.event_type {
        q = q.bind(event_type);
    }
    if let Some(ref category) = query.category {
        q = q.bind(format!("{category}.%"));
    }
    if let Some(ref severity) = query.severity {
        q = q.bind(severity);
    }
    if let Some(ref subject) = query.subject {
        q = q.bind(subject);
    }
    if let Some(ref cursor) = query.cursor {
        let ts = cursor
            .parse::<chrono::DateTime<chrono::Utc>>()
            .map_err(|_| AppError::BadRequest("invalid cursor format".to_string()))?;
        q = q.bind(ts);
    }
    q = q.bind(limit);

    let rows = q
        .fetch_all(&state.db)
        .await
        .map_err(|e| AppError::Internal(format!("failed to query events: {e}")))?;

    let events: Vec<EventResponse> = rows
        .into_iter()
        .map(|row| EventResponse {
            id: row.0,
            event_type: row.1,
            severity: row.2,
            actor_did: row.3,
            subject: row.4,
            detail: row.5,
            created_at: row.6,
        })
        .collect();

    let cursor = events.last().map(|e| e.created_at.to_rfc3339());

    Ok(Json(EventsListResponse { events, cursor }))
}
