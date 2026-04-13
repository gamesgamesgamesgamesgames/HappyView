use axum::Json;
use axum::extract::State;
use axum::http::StatusCode;

use crate::AppState;
use crate::db::{adapt_sql, now_rfc3339};
use crate::error::AppError;
use crate::event_log::{EventLog, Severity, log_event};

use super::auth::UserAuth;
use super::permissions::Permission;
use super::types::{RateLimitsResponse, SetEnabledBody, UpsertRateLimitBody};

/// GET /admin/rate-limits — list rate limit config.
pub(super) async fn list(
    State(state): State<AppState>,
    auth: UserAuth,
) -> Result<Json<RateLimitsResponse>, AppError> {
    auth.require(Permission::RateLimitsRead).await?;

    let backend = state.db_backend;

    let enabled_sql = adapt_sql(
        "SELECT value FROM rate_limit_settings WHERE key = 'enabled'",
        backend,
    );
    let enabled: String = sqlx::query_scalar(&enabled_sql)
        .fetch_optional(&state.db)
        .await
        .map_err(|e| AppError::Internal(format!("failed to read rate limit settings: {e}")))?
        .unwrap_or_else(|| "true".to_string());

    let limits_sql = adapt_sql(
        "SELECT capacity, refill_rate, default_query_cost, default_procedure_cost, default_proxy_cost FROM rate_limits WHERE method IS NULL",
        backend,
    );
    let row: Option<(i32, f64, i32, i32, i32)> = sqlx::query_as(&limits_sql)
        .fetch_optional(&state.db)
        .await
        .map_err(|e| AppError::Internal(format!("failed to read rate limits: {e}")))?;

    let (capacity, refill_rate, default_query_cost, default_procedure_cost, default_proxy_cost) =
        row.unwrap_or((100, 2.0, 1, 1, 1));

    Ok(Json(RateLimitsResponse {
        enabled: enabled == "true",
        capacity,
        refill_rate,
        default_query_cost,
        default_procedure_cost,
        default_proxy_cost,
    }))
}

/// POST /admin/rate-limits — upsert the global rate limit config.
pub(super) async fn upsert(
    State(state): State<AppState>,
    auth: UserAuth,
    Json(body): Json<UpsertRateLimitBody>,
) -> Result<StatusCode, AppError> {
    auth.require(Permission::RateLimitsCreate).await?;

    let backend = state.db_backend;
    let now = now_rfc3339();
    let sql = adapt_sql(
        r#"
        INSERT INTO rate_limits (method, capacity, refill_rate, default_query_cost, default_procedure_cost, default_proxy_cost, created_at)
        VALUES (NULL, ?, ?, ?, ?, ?, ?)
        ON CONFLICT (method) DO UPDATE SET
            capacity = EXCLUDED.capacity,
            refill_rate = EXCLUDED.refill_rate,
            default_query_cost = EXCLUDED.default_query_cost,
            default_procedure_cost = EXCLUDED.default_procedure_cost,
            default_proxy_cost = EXCLUDED.default_proxy_cost,
            updated_at = ?
        "#,
        backend,
    );
    sqlx::query(&sql)
        .bind(body.capacity as i32)
        .bind(body.refill_rate)
        .bind(body.default_query_cost as i32)
        .bind(body.default_procedure_cost as i32)
        .bind(body.default_proxy_cost as i32)
        .bind(&now)
        .bind(&now)
        .execute(&state.db)
        .await
        .map_err(|e| AppError::Internal(format!("failed to upsert rate limit: {e}")))?;

    state.rate_limiter.reload_from_db(&state.db).await;

    log_event(
        &state.db,
        EventLog {
            event_type: "rate_limit.upserted".to_string(),
            severity: Severity::Info,
            actor_did: Some(auth.did.clone()),
            subject: None,
            detail: serde_json::json!({
                "capacity": body.capacity,
                "refill_rate": body.refill_rate,
                "default_query_cost": body.default_query_cost,
                "default_procedure_cost": body.default_procedure_cost,
                "default_proxy_cost": body.default_proxy_cost,
            }),
        },
        state.db_backend,
    )
    .await;

    Ok(StatusCode::CREATED)
}

/// PUT /admin/rate-limits/enabled — toggle rate limiting.
pub(super) async fn set_enabled(
    State(state): State<AppState>,
    auth: UserAuth,
    Json(body): Json<SetEnabledBody>,
) -> Result<StatusCode, AppError> {
    auth.require(Permission::RateLimitsCreate).await?;

    let value = if body.enabled { "true" } else { "false" };

    let backend = state.db_backend;
    let now = now_rfc3339();
    let sql = adapt_sql(
        r#"
        INSERT INTO rate_limit_settings (key, value)
        VALUES ('enabled', ?)
        ON CONFLICT (key) DO UPDATE SET value = EXCLUDED.value, updated_at = ?
        "#,
        backend,
    );
    sqlx::query(&sql)
        .bind(value)
        .bind(&now)
        .execute(&state.db)
        .await
        .map_err(|e| AppError::Internal(format!("failed to update rate limit settings: {e}")))?;

    state.rate_limiter.set_enabled(body.enabled);

    log_event(
        &state.db,
        EventLog {
            event_type: "rate_limit.toggled".to_string(),
            severity: Severity::Info,
            actor_did: Some(auth.did.clone()),
            subject: None,
            detail: serde_json::json!({ "enabled": body.enabled }),
        },
        state.db_backend,
    )
    .await;

    Ok(StatusCode::NO_CONTENT)
}
