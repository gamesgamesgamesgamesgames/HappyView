use axum::Json;
use axum::extract::{Path, State};
use axum::http::StatusCode;

use crate::AppState;
use crate::error::AppError;
use crate::event_log::{EventLog, Severity, log_event};

use super::auth::UserAuth;
use super::permissions::Permission;
use super::types::{
    AddAllowlistBody, AllowlistEntry, RateLimitSummary, RateLimitsResponse, SetEnabledBody,
    UpsertRateLimitBody,
};

/// GET /admin/rate-limits — list rate limit config.
pub(super) async fn list(
    State(state): State<AppState>,
    auth: UserAuth,
) -> Result<Json<RateLimitsResponse>, AppError> {
    auth.require(Permission::RateLimitsRead).await?;

    let enabled: String =
        sqlx::query_scalar("SELECT value FROM rate_limit_settings WHERE key = 'enabled'")
            .fetch_optional(&state.db)
            .await
            .map_err(|e| AppError::Internal(format!("failed to read rate limit settings: {e}")))?
            .unwrap_or_else(|| "true".to_string());

    let limits: Vec<RateLimitSummary> = sqlx::query_as(
        "SELECT id, method, capacity, refill_rate, created_at, updated_at FROM rate_limits ORDER BY id",
    )
    .fetch_all(&state.db)
    .await
    .map_err(|e| AppError::Internal(format!("failed to list rate limits: {e}")))?;

    let allowlist: Vec<AllowlistEntry> =
        sqlx::query_as("SELECT id, cidr, note, created_at FROM rate_limit_allowlist ORDER BY id")
            .fetch_all(&state.db)
            .await
            .map_err(|e| AppError::Internal(format!("failed to list allowlist: {e}")))?;

    Ok(Json(RateLimitsResponse {
        enabled: enabled == "true",
        limits,
        allowlist,
    }))
}

/// POST /admin/rate-limits — upsert a rate limit rule.
pub(super) async fn upsert(
    State(state): State<AppState>,
    auth: UserAuth,
    Json(body): Json<UpsertRateLimitBody>,
) -> Result<StatusCode, AppError> {
    auth.require(Permission::RateLimitsCreate).await?;

    sqlx::query(
        r#"
        INSERT INTO rate_limits (method, capacity, refill_rate)
        VALUES ($1, $2, $3)
        ON CONFLICT (method) DO UPDATE SET
            capacity = EXCLUDED.capacity,
            refill_rate = EXCLUDED.refill_rate,
            updated_at = NOW()
        "#,
    )
    .bind(&body.method)
    .bind(body.capacity as i32)
    .bind(body.refill_rate as f32)
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
            subject: body.method.clone(),
            detail: serde_json::json!({
                "capacity": body.capacity,
                "refill_rate": body.refill_rate,
            }),
        },
    )
    .await;

    Ok(StatusCode::CREATED)
}

/// DELETE /admin/rate-limits/{id} — delete a rate limit rule.
pub(super) async fn delete(
    State(state): State<AppState>,
    auth: UserAuth,
    Path(id): Path<i32>,
) -> Result<StatusCode, AppError> {
    auth.require(Permission::RateLimitsDelete).await?;

    // Prevent deleting the global default (method IS NULL)
    let is_global: Option<(bool,)> =
        sqlx::query_as("SELECT (method IS NULL) FROM rate_limits WHERE id = $1")
            .bind(id)
            .fetch_optional(&state.db)
            .await
            .map_err(|e| AppError::Internal(format!("failed to check rate limit: {e}")))?;

    match is_global {
        None => {
            return Err(AppError::NotFound(format!(
                "rate limit rule {id} not found"
            )));
        }
        Some((true,)) => {
            return Err(AppError::BadRequest(
                "cannot delete the global default rate limit".to_string(),
            ));
        }
        Some((false,)) => {}
    }

    sqlx::query("DELETE FROM rate_limits WHERE id = $1")
        .bind(id)
        .execute(&state.db)
        .await
        .map_err(|e| AppError::Internal(format!("failed to delete rate limit: {e}")))?;

    state.rate_limiter.reload_from_db(&state.db).await;

    log_event(
        &state.db,
        EventLog {
            event_type: "rate_limit.deleted".to_string(),
            severity: Severity::Info,
            actor_did: Some(auth.did.clone()),
            subject: Some(id.to_string()),
            detail: serde_json::json!({}),
        },
    )
    .await;

    Ok(StatusCode::NO_CONTENT)
}

/// PUT /admin/rate-limits/enabled — toggle rate limiting.
pub(super) async fn set_enabled(
    State(state): State<AppState>,
    auth: UserAuth,
    Json(body): Json<SetEnabledBody>,
) -> Result<StatusCode, AppError> {
    auth.require(Permission::RateLimitsCreate).await?;

    let value = if body.enabled { "true" } else { "false" };

    sqlx::query(
        r#"
        INSERT INTO rate_limit_settings (key, value)
        VALUES ('enabled', $1)
        ON CONFLICT (key) DO UPDATE SET value = EXCLUDED.value, updated_at = NOW()
        "#,
    )
    .bind(value)
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
    )
    .await;

    Ok(StatusCode::NO_CONTENT)
}

/// POST /admin/rate-limits/allowlist — add an IP/CIDR to the allowlist.
pub(super) async fn add_allowlist(
    State(state): State<AppState>,
    auth: UserAuth,
    Json(body): Json<AddAllowlistBody>,
) -> Result<StatusCode, AppError> {
    auth.require(Permission::RateLimitsCreate).await?;

    // Validate CIDR syntax; if it's a bare IP, append /32 or /128
    let cidr_str = if body.cidr.contains('/') {
        body.cidr.clone()
    } else if let Ok(ip) = body.cidr.parse::<std::net::IpAddr>() {
        match ip {
            std::net::IpAddr::V4(_) => format!("{}/32", body.cidr),
            std::net::IpAddr::V6(_) => format!("{}/128", body.cidr),
        }
    } else {
        return Err(AppError::BadRequest(format!(
            "invalid IP or CIDR: {}",
            body.cidr
        )));
    };

    // Validate it parses as IpNet
    if cidr_str.parse::<ipnet::IpNet>().is_err() {
        return Err(AppError::BadRequest(format!("invalid CIDR: {}", cidr_str)));
    }

    sqlx::query("INSERT INTO rate_limit_allowlist (cidr, note) VALUES ($1, $2)")
        .bind(&cidr_str)
        .bind(&body.note)
        .execute(&state.db)
        .await
        .map_err(|e| AppError::Internal(format!("failed to add allowlist entry: {e}")))?;

    state.rate_limiter.reload_from_db(&state.db).await;

    log_event(
        &state.db,
        EventLog {
            event_type: "rate_limit.allowlist_added".to_string(),
            severity: Severity::Info,
            actor_did: Some(auth.did.clone()),
            subject: Some(cidr_str),
            detail: serde_json::json!({ "note": body.note }),
        },
    )
    .await;

    Ok(StatusCode::CREATED)
}

/// DELETE /admin/rate-limits/allowlist/{id} — remove an allowlist entry.
pub(super) async fn remove_allowlist(
    State(state): State<AppState>,
    auth: UserAuth,
    Path(id): Path<i32>,
) -> Result<StatusCode, AppError> {
    auth.require(Permission::RateLimitsDelete).await?;

    let result = sqlx::query("DELETE FROM rate_limit_allowlist WHERE id = $1")
        .bind(id)
        .execute(&state.db)
        .await
        .map_err(|e| AppError::Internal(format!("failed to delete allowlist entry: {e}")))?;

    if result.rows_affected() == 0 {
        return Err(AppError::NotFound(format!(
            "allowlist entry {id} not found"
        )));
    }

    state.rate_limiter.reload_from_db(&state.db).await;

    log_event(
        &state.db,
        EventLog {
            event_type: "rate_limit.allowlist_removed".to_string(),
            severity: Severity::Info,
            actor_did: Some(auth.did.clone()),
            subject: Some(id.to_string()),
            detail: serde_json::json!({}),
        },
    )
    .await;

    Ok(StatusCode::NO_CONTENT)
}
