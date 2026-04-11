use axum::Json;
use axum::extract::{Path, State};
use axum::http::StatusCode;
use base64::Engine;
use sqlx::AnyPool;
use std::env;

use crate::AppState;
use crate::db::{DatabaseBackend, adapt_sql, now_rfc3339};
use crate::error::AppError;
use crate::event_log::{EventLog, Severity, log_event};

use super::auth::UserAuth;
use super::permissions::Permission;
use super::types::{SettingEntry, UpsertSettingBody};

const ENV_FALLBACKS: &[(&str, &str)] = &[
    ("app_name", "APP_NAME"),
    ("client_uri", "CLIENT_URI"),
    ("logo_uri", "LOGO_URI"),
    ("tos_uri", "TOS_URI"),
    ("policy_uri", "POLICY_URI"),
    ("oauth_scopes", "OAUTH_SCOPES"),
];

/// Resolve a setting value: check the DB first, then fall back to env var.
pub async fn get_setting(pool: &AnyPool, key: &str, backend: DatabaseBackend) -> Option<String> {
    let sql = adapt_sql("SELECT value FROM instance_settings WHERE key = ?", backend);
    let row: Option<(String,)> = sqlx::query_as(&sql)
        .bind(key)
        .fetch_optional(pool)
        .await
        .ok()
        .flatten();

    if let Some((value,)) = row {
        return Some(value);
    }

    // Fall back to env var if one is mapped for this key.
    for (setting_key, env_var) in ENV_FALLBACKS {
        if *setting_key == key {
            return env::var(env_var).ok();
        }
    }

    None
}

/// GET /admin/settings — list all settings with their source.
pub(super) async fn list(
    State(state): State<AppState>,
    auth: UserAuth,
) -> Result<Json<Vec<SettingEntry>>, AppError> {
    auth.require(Permission::SettingsManage).await?;

    let backend = state.db_backend;
    let sql = adapt_sql(
        "SELECT key, value FROM instance_settings ORDER BY key",
        backend,
    );
    let rows: Vec<(String, String)> = sqlx::query_as(&sql)
        .fetch_all(&state.db)
        .await
        .map_err(|e| AppError::Internal(format!("failed to list settings: {e}")))?;

    let db_keys: std::collections::HashSet<String> = rows.iter().map(|(k, _)| k.clone()).collect();

    let mut entries: Vec<SettingEntry> = rows
        .into_iter()
        .map(|(key, value)| SettingEntry {
            key,
            value,
            source: "database".to_string(),
        })
        .collect();

    // Add env-var fallback entries for keys not already present in DB.
    for (setting_key, env_var) in ENV_FALLBACKS {
        if !db_keys.contains(*setting_key)
            && let Ok(value) = env::var(env_var)
        {
            entries.push(SettingEntry {
                key: setting_key.to_string(),
                value,
                source: "env".to_string(),
            });
        }
    }

    Ok(Json(entries))
}

/// PUT /admin/settings/{key} — create or update a setting.
pub(super) async fn upsert(
    State(state): State<AppState>,
    auth: UserAuth,
    Path(key): Path<String>,
    Json(body): Json<UpsertSettingBody>,
) -> Result<StatusCode, AppError> {
    auth.require(Permission::SettingsManage).await?;

    let backend = state.db_backend;
    let now = now_rfc3339();
    let sql = adapt_sql(
        r#"
        INSERT INTO instance_settings (key, value, updated_at)
        VALUES (?, ?, ?)
        ON CONFLICT (key) DO UPDATE SET value = ?, updated_at = ?
        "#,
        backend,
    );
    sqlx::query(&sql)
        .bind(&key)
        .bind(&body.value)
        .bind(&now)
        .bind(&body.value)
        .bind(&now)
        .execute(&state.db)
        .await
        .map_err(|e| AppError::Internal(format!("failed to upsert setting: {e}")))?;

    log_event(
        &state.db,
        EventLog {
            event_type: "setting.updated".to_string(),
            severity: Severity::Info,
            actor_did: Some(auth.did.clone()),
            subject: Some(key.clone()),
            detail: serde_json::json!({ "value": body.value }),
        },
        state.db_backend,
    )
    .await;

    Ok(StatusCode::NO_CONTENT)
}

/// DELETE /admin/settings/{key} — delete a setting.
pub(super) async fn delete(
    State(state): State<AppState>,
    auth: UserAuth,
    Path(key): Path<String>,
) -> Result<StatusCode, AppError> {
    auth.require(Permission::SettingsManage).await?;

    let backend = state.db_backend;
    let sql = adapt_sql("DELETE FROM instance_settings WHERE key = ?", backend);
    let result = sqlx::query(&sql)
        .bind(&key)
        .execute(&state.db)
        .await
        .map_err(|e| AppError::Internal(format!("failed to delete setting: {e}")))?;

    if result.rows_affected() == 0 {
        return Err(AppError::NotFound(format!("setting '{key}' not found")));
    }

    log_event(
        &state.db,
        EventLog {
            event_type: "setting.deleted".to_string(),
            severity: Severity::Info,
            actor_did: Some(auth.did.clone()),
            subject: Some(key),
            detail: serde_json::json!({}),
        },
        state.db_backend,
    )
    .await;

    Ok(StatusCode::NO_CONTENT)
}

/// PUT /admin/settings/logo — upload a logo image (max 5MB).
pub(super) async fn upload_logo(
    State(state): State<AppState>,
    auth: UserAuth,
    mut multipart: axum::extract::Multipart,
) -> Result<StatusCode, AppError> {
    auth.require(Permission::SettingsManage).await?;

    let field = multipart
        .next_field()
        .await
        .map_err(|e| AppError::BadRequest(format!("invalid multipart: {e}")))?
        .ok_or_else(|| AppError::BadRequest("no file uploaded".into()))?;

    let content_type = field
        .content_type()
        .unwrap_or("application/octet-stream")
        .to_string();

    if !content_type.starts_with("image/") {
        return Err(AppError::BadRequest("file must be an image".into()));
    }

    let data = field
        .bytes()
        .await
        .map_err(|e| AppError::BadRequest(format!("failed to read upload: {e}")))?;

    if data.len() > 5 * 1024 * 1024 {
        return Err(AppError::BadRequest("logo must be 5MB or smaller".into()));
    }

    let encoded = base64::engine::general_purpose::STANDARD.encode(&data);

    let backend = state.db_backend;
    let now = now_rfc3339();
    let sql = adapt_sql(
        "INSERT INTO instance_settings (key, value, updated_at) VALUES (?, ?, ?) ON CONFLICT (key) DO UPDATE SET value = ?, updated_at = ?",
        backend,
    );
    for (key, value) in [
        ("logo_data", encoded.as_str()),
        ("logo_content_type", content_type.as_str()),
    ] {
        sqlx::query(&sql)
            .bind(key)
            .bind(value)
            .bind(&now)
            .bind(value)
            .bind(&now)
            .execute(&state.db)
            .await
            .map_err(|e| AppError::Internal(format!("failed to store logo: {e}")))?;
    }

    log_event(
        &state.db,
        EventLog {
            event_type: "setting.updated".to_string(),
            severity: Severity::Info,
            actor_did: Some(auth.did.clone()),
            subject: Some("logo".to_string()),
            detail: serde_json::json!({ "content_type": content_type, "size_bytes": data.len() }),
        },
        state.db_backend,
    )
    .await;

    Ok(StatusCode::NO_CONTENT)
}

/// DELETE /admin/settings/logo — remove uploaded logo.
pub(super) async fn delete_logo(
    State(state): State<AppState>,
    auth: UserAuth,
) -> Result<StatusCode, AppError> {
    auth.require(Permission::SettingsManage).await?;

    let backend = state.db_backend;
    let sql = adapt_sql("DELETE FROM instance_settings WHERE key IN (?, ?)", backend);
    sqlx::query(&sql)
        .bind("logo_data")
        .bind("logo_content_type")
        .execute(&state.db)
        .await
        .map_err(|e| AppError::Internal(format!("failed to delete logo: {e}")))?;

    log_event(
        &state.db,
        EventLog {
            event_type: "setting.deleted".to_string(),
            severity: Severity::Info,
            actor_did: Some(auth.did.clone()),
            subject: Some("logo".to_string()),
            detail: serde_json::json!({}),
        },
        state.db_backend,
    )
    .await;

    Ok(StatusCode::NO_CONTENT)
}

/// GET /settings/logo — serve the uploaded logo (public, no auth).
pub(crate) async fn serve_logo(
    State(state): State<AppState>,
) -> Result<axum::response::Response, AppError> {
    let backend = state.db_backend;
    let sql = adapt_sql(
        "SELECT key, value FROM instance_settings WHERE key IN (?, ?)",
        backend,
    );
    let rows: Vec<(String, String)> = sqlx::query_as(&sql)
        .bind("logo_data")
        .bind("logo_content_type")
        .fetch_all(&state.db)
        .await
        .map_err(|e| AppError::Internal(format!("failed to load logo: {e}")))?;

    let data = rows.iter().find(|(k, _)| k == "logo_data").map(|(_, v)| v);
    let ct = rows
        .iter()
        .find(|(k, _)| k == "logo_content_type")
        .map(|(_, v)| v.as_str());

    match (data, ct) {
        (Some(encoded), Some(content_type)) => {
            let bytes = base64::engine::general_purpose::STANDARD
                .decode(encoded)
                .map_err(|e| AppError::Internal(format!("failed to decode logo: {e}")))?;
            Ok(axum::response::Response::builder()
                .header("content-type", content_type)
                .header("cache-control", "public, max-age=3600")
                .body(axum::body::Body::from(bytes))
                .unwrap())
        }
        _ => Err(AppError::NotFound("no logo uploaded".into())),
    }
}
