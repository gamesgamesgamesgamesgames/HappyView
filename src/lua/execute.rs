use axum::Json;
use axum::response::{IntoResponse, Response};
use mlua::LuaSerdeExt;
use serde_json::Value;
use std::collections::HashMap;
use std::sync::Arc;
use std::time::Instant;

use crate::AppState;
use crate::auth::Claims;
use crate::error::AppError;
use crate::event_log::{EventLog, Severity, log_event};
use crate::lexicon::ParsedLexicon;
use crate::repo;

use super::context;
use super::db_api;
use super::http_api;
use super::record;
use super::sandbox;

/// Execute a Lua script for a procedure endpoint.
pub async fn execute_procedure_script(
    state: &AppState,
    method: &str,
    claims: &Claims,
    input: &Value,
    lexicon: &ParsedLexicon,
    script: &str,
) -> Result<Response, AppError> {
    let start = Instant::now();
    let collection = lexicon.target_collection.as_deref().unwrap_or_default();

    // Capture script source and input for error logging before anything is consumed.
    let script_source = script.to_string();
    let input_json = input.clone();

    let session = match repo::get_atp_session(state, claims.token()).await {
        Ok(s) => s,
        Err(e) => {
            let error_message = format!("{e}");
            log_event(
                &state.db,
                EventLog {
                    event_type: "script.error".to_string(),
                    severity: Severity::Error,
                    actor_did: Some(claims.did().to_string()),
                    subject: Some(method.to_string()),
                    detail: serde_json::json!({
                        "error": error_message,
                        "script_source": script_source,
                        "input": input_json,
                        "caller_did": claims.did(),
                        "method": method,
                    }),
                },
            )
            .await;
            return Err(e);
        }
    };

    let lua = match sandbox::create_sandbox() {
        Ok(l) => l,
        Err(e) => {
            let error_message = format!("failed to create Lua VM: {e}");
            log_event(
                &state.db,
                EventLog {
                    event_type: "script.error".to_string(),
                    severity: Severity::Error,
                    actor_did: Some(claims.did().to_string()),
                    subject: Some(method.to_string()),
                    detail: serde_json::json!({
                        "error": error_message,
                        "script_source": script_source,
                        "input": input_json,
                        "caller_did": claims.did(),
                        "method": method,
                    }),
                },
            )
            .await;
            return Err(AppError::Internal(error_message));
        }
    };

    let state_arc = Arc::new(state.clone());
    let claims_arc = Arc::new(claims.clone());
    let session_arc = Arc::new(session);

    if let Err(e) = db_api::register_db_api(&lua, state_arc.clone()) {
        let error_message = format!("failed to register db API: {e}");
        log_event(
            &state.db,
            EventLog {
                event_type: "script.error".to_string(),
                severity: Severity::Error,
                actor_did: Some(claims.did().to_string()),
                subject: Some(method.to_string()),
                detail: serde_json::json!({
                    "error": error_message,
                    "script_source": script_source,
                    "input": input_json,
                    "caller_did": claims.did(),
                    "method": method,
                }),
            },
        )
        .await;
        return Err(AppError::Internal(error_message));
    }

    if let Err(e) = http_api::register_http_api(&lua, state_arc.clone()) {
        let error_message = format!("failed to register http API: {e}");
        log_event(
            &state.db,
            EventLog {
                event_type: "script.error".to_string(),
                severity: Severity::Error,
                actor_did: Some(claims.did().to_string()),
                subject: Some(method.to_string()),
                detail: serde_json::json!({
                    "error": error_message,
                    "script_source": script_source,
                    "input": input_json,
                    "caller_did": claims.did(),
                    "method": method,
                }),
            },
        )
        .await;
        return Err(AppError::Internal(error_message));
    }

    if let Err(e) = record::register_record_api(&lua, state_arc, claims_arc, session_arc) {
        let error_message = format!("failed to register Record API: {e}");
        log_event(
            &state.db,
            EventLog {
                event_type: "script.error".to_string(),
                severity: Severity::Error,
                actor_did: Some(claims.did().to_string()),
                subject: Some(method.to_string()),
                detail: serde_json::json!({
                    "error": error_message,
                    "script_source": script_source,
                    "input": input_json,
                    "caller_did": claims.did(),
                    "method": method,
                }),
            },
        )
        .await;
        return Err(AppError::Internal(error_message));
    }

    if let Err(e) = context::set_procedure_context(&lua, method, input, claims.did(), collection) {
        let error_message = format!("failed to set context: {e}");
        log_event(
            &state.db,
            EventLog {
                event_type: "script.error".to_string(),
                severity: Severity::Error,
                actor_did: Some(claims.did().to_string()),
                subject: Some(method.to_string()),
                detail: serde_json::json!({
                    "error": error_message,
                    "script_source": script_source,
                    "input": input_json,
                    "caller_did": claims.did(),
                    "method": method,
                }),
            },
        )
        .await;
        return Err(AppError::Internal(error_message));
    }

    if let Err(e) = lua.load(script).exec() {
        let error_message = format!("{e}");
        tracing::error!(method, error = %e, "lua script load failed");
        log_event(
            &state.db,
            EventLog {
                event_type: "script.error".to_string(),
                severity: Severity::Error,
                actor_did: Some(claims.did().to_string()),
                subject: Some(method.to_string()),
                detail: serde_json::json!({
                    "error": error_message,
                    "script_source": script_source,
                    "input": input_json,
                    "caller_did": claims.did(),
                    "method": method,
                }),
            },
        )
        .await;
        return Err(AppError::Internal("script execution failed".into()));
    }

    let handle: mlua::Function = match lua.globals().get("handle") {
        Ok(f) => f,
        Err(e) => {
            let error_message = format!("{e}");
            tracing::error!(method, error = %e, "lua script missing handle function");
            log_event(
                &state.db,
                EventLog {
                    event_type: "script.error".to_string(),
                    severity: Severity::Error,
                    actor_did: Some(claims.did().to_string()),
                    subject: Some(method.to_string()),
                    detail: serde_json::json!({
                        "error": error_message,
                        "script_source": script_source,
                        "input": input_json,
                        "caller_did": claims.did(),
                        "method": method,
                    }),
                },
            )
            .await;
            return Err(AppError::Internal("script execution failed".into()));
        }
    };

    let result: mlua::Value = match handle.call_async(()).await {
        Ok(r) => r,
        Err(e) => {
            let msg = e.to_string();
            tracing::error!(method, error = %msg, "lua script execution failed");
            let app_error = if msg.contains("execution limit") {
                AppError::Internal("script exceeded execution time limit".into())
            } else {
                AppError::Internal("script execution failed".into())
            };
            log_event(
                &state.db,
                EventLog {
                    event_type: "script.error".to_string(),
                    severity: Severity::Error,
                    actor_did: Some(claims.did().to_string()),
                    subject: Some(method.to_string()),
                    detail: serde_json::json!({
                        "error": msg,
                        "script_source": script_source,
                        "input": input_json,
                        "caller_did": claims.did(),
                        "method": method,
                    }),
                },
            )
            .await;
            return Err(app_error);
        }
    };

    let json_value: Value = match lua.from_value(result) {
        Ok(v) => v,
        Err(e) => {
            let error_message = format!("{e}");
            tracing::error!(method, error = %e, "failed to convert lua result to JSON");
            log_event(
                &state.db,
                EventLog {
                    event_type: "script.error".to_string(),
                    severity: Severity::Error,
                    actor_did: Some(claims.did().to_string()),
                    subject: Some(method.to_string()),
                    detail: serde_json::json!({
                        "error": error_message,
                        "script_source": script_source,
                        "input": input_json,
                        "caller_did": claims.did(),
                        "method": method,
                    }),
                },
            )
            .await;
            return Err(AppError::Internal("script execution failed".into()));
        }
    };

    log_event(
        &state.db,
        EventLog {
            event_type: "script.executed".to_string(),
            severity: Severity::Info,
            actor_did: Some(claims.did().to_string()),
            subject: Some(method.to_string()),
            detail: serde_json::json!({
                "method": method,
                "caller_did": claims.did(),
                "duration_ms": start.elapsed().as_millis() as u64,
            }),
        },
    )
    .await;

    Ok(Json(json_value).into_response())
}

/// Execute a Lua script for a query endpoint.
pub async fn execute_query_script(
    state: &AppState,
    method: &str,
    params: &HashMap<String, String>,
    lexicon: &ParsedLexicon,
    script: &str,
) -> Result<Response, AppError> {
    let start = Instant::now();
    let collection = lexicon.target_collection.as_deref().unwrap_or_default();

    // Capture script source for error logging.
    let script_source = script.to_string();

    let lua = match sandbox::create_sandbox() {
        Ok(l) => l,
        Err(e) => {
            let error_message = format!("failed to create Lua VM: {e}");
            log_event(
                &state.db,
                EventLog {
                    event_type: "script.error".to_string(),
                    severity: Severity::Error,
                    actor_did: None,
                    subject: Some(method.to_string()),
                    detail: serde_json::json!({
                        "error": error_message,
                        "script_source": script_source,
                        "method": method,
                    }),
                },
            )
            .await;
            return Err(AppError::Internal(error_message));
        }
    };

    let state_arc = Arc::new(state.clone());

    if let Err(e) = db_api::register_db_api(&lua, state_arc.clone()) {
        let error_message = format!("failed to register db API: {e}");
        log_event(
            &state.db,
            EventLog {
                event_type: "script.error".to_string(),
                severity: Severity::Error,
                actor_did: None,
                subject: Some(method.to_string()),
                detail: serde_json::json!({
                    "error": error_message,
                    "script_source": script_source,
                    "method": method,
                }),
            },
        )
        .await;
        return Err(AppError::Internal(error_message));
    }

    if let Err(e) = http_api::register_http_api(&lua, state_arc) {
        let error_message = format!("failed to register http API: {e}");
        log_event(
            &state.db,
            EventLog {
                event_type: "script.error".to_string(),
                severity: Severity::Error,
                actor_did: None,
                subject: Some(method.to_string()),
                detail: serde_json::json!({
                    "error": error_message,
                    "script_source": script_source,
                    "method": method,
                }),
            },
        )
        .await;
        return Err(AppError::Internal(error_message));
    }

    if let Err(e) = context::set_query_context(&lua, method, params, collection) {
        let error_message = format!("failed to set context: {e}");
        log_event(
            &state.db,
            EventLog {
                event_type: "script.error".to_string(),
                severity: Severity::Error,
                actor_did: None,
                subject: Some(method.to_string()),
                detail: serde_json::json!({
                    "error": error_message,
                    "script_source": script_source,
                    "method": method,
                }),
            },
        )
        .await;
        return Err(AppError::Internal(error_message));
    }

    if let Err(e) = lua.load(script).exec() {
        let error_message = format!("{e}");
        tracing::error!(method, error = %e, "lua script load failed");
        log_event(
            &state.db,
            EventLog {
                event_type: "script.error".to_string(),
                severity: Severity::Error,
                actor_did: None,
                subject: Some(method.to_string()),
                detail: serde_json::json!({
                    "error": error_message,
                    "script_source": script_source,
                    "method": method,
                }),
            },
        )
        .await;
        return Err(AppError::Internal("script execution failed".into()));
    }

    let handle: mlua::Function = match lua.globals().get("handle") {
        Ok(f) => f,
        Err(e) => {
            let error_message = format!("{e}");
            tracing::error!(method, error = %e, "lua script missing handle function");
            log_event(
                &state.db,
                EventLog {
                    event_type: "script.error".to_string(),
                    severity: Severity::Error,
                    actor_did: None,
                    subject: Some(method.to_string()),
                    detail: serde_json::json!({
                        "error": error_message,
                        "script_source": script_source,
                        "method": method,
                    }),
                },
            )
            .await;
            return Err(AppError::Internal("script execution failed".into()));
        }
    };

    let result: mlua::Value = match handle.call_async(()).await {
        Ok(r) => r,
        Err(e) => {
            let msg = e.to_string();
            tracing::error!(method, error = %msg, "lua script execution failed");
            let app_error = if msg.contains("execution limit") {
                AppError::Internal("script exceeded execution time limit".into())
            } else {
                AppError::Internal("script execution failed".into())
            };
            log_event(
                &state.db,
                EventLog {
                    event_type: "script.error".to_string(),
                    severity: Severity::Error,
                    actor_did: None,
                    subject: Some(method.to_string()),
                    detail: serde_json::json!({
                        "error": msg,
                        "script_source": script_source,
                        "method": method,
                    }),
                },
            )
            .await;
            return Err(app_error);
        }
    };

    let json_value: Value = match lua.from_value(result) {
        Ok(v) => v,
        Err(e) => {
            let error_message = format!("{e}");
            tracing::error!(method, error = %e, "failed to convert lua result to JSON");
            log_event(
                &state.db,
                EventLog {
                    event_type: "script.error".to_string(),
                    severity: Severity::Error,
                    actor_did: None,
                    subject: Some(method.to_string()),
                    detail: serde_json::json!({
                        "error": error_message,
                        "script_source": script_source,
                        "method": method,
                    }),
                },
            )
            .await;
            return Err(AppError::Internal("script execution failed".into()));
        }
    };

    log_event(
        &state.db,
        EventLog {
            event_type: "script.executed".to_string(),
            severity: Severity::Info,
            actor_did: None,
            subject: Some(method.to_string()),
            detail: serde_json::json!({
                "method": method,
                "duration_ms": start.elapsed().as_millis() as u64,
            }),
        },
    )
    .await;

    Ok(Json(json_value).into_response())
}

/// Context for a hook execution triggered by a record index event.
pub struct HookEvent<'a> {
    pub state: &'a AppState,
    pub lexicon_id: &'a str,
    pub script: &'a str,
    pub action: &'a str,
    pub uri: &'a str,
    pub did: &'a str,
    pub collection: &'a str,
    pub rkey: &'a str,
    pub record: Option<&'a Value>,
}

/// Execute a Lua hook script triggered by a record index event.
///
/// Retries up to 3 times with exponential backoff (1s, 2s, 4s).
/// On final failure, inserts into `dead_letter_hooks` table.
pub async fn execute_hook_script(event: &HookEvent<'_>) {
    let max_attempts: i32 = 4; // 1 initial + 3 retries
    let mut last_error = String::new();

    for attempt in 0..max_attempts {
        if attempt > 0 {
            let delay = std::time::Duration::from_secs(1 << (attempt - 1)); // 1s, 2s, 4s
            tokio::time::sleep(delay).await;
        }

        match run_hook_once(event).await {
            Ok(()) => {
                log_event(
                    &event.state.db,
                    EventLog {
                        event_type: "hook.executed".to_string(),
                        severity: Severity::Info,
                        actor_did: None,
                        subject: Some(event.uri.to_string()),
                        detail: serde_json::json!({
                            "lexicon_id": event.lexicon_id,
                            "action": event.action,
                            "collection": event.collection,
                            "attempts": attempt + 1,
                        }),
                    },
                )
                .await;
                return;
            }
            Err(e) => {
                last_error = e;
                tracing::warn!(
                    uri = event.uri,
                    lexicon_id = event.lexicon_id,
                    attempt = attempt + 1,
                    "hook execution failed: {last_error}"
                );
            }
        }
    }

    // All retries exhausted — dead-letter the event.
    tracing::error!(
        uri = event.uri,
        lexicon_id = event.lexicon_id,
        "hook dead-lettered after {max_attempts} attempts"
    );

    if let Err(e) = sqlx::query(
        r#"
        INSERT INTO dead_letter_hooks (lexicon_id, uri, did, collection, rkey, action, record, error, attempts)
        VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
        "#,
    )
    .bind(event.lexicon_id)
    .bind(event.uri)
    .bind(event.did)
    .bind(event.collection)
    .bind(event.rkey)
    .bind(event.action)
    .bind(event.record)
    .bind(&last_error)
    .bind(max_attempts)
    .execute(&event.state.db)
    .await
    {
        tracing::error!(uri = event.uri, "failed to insert dead letter hook: {e}");
    }

    log_event(
        &event.state.db,
        EventLog {
            event_type: "hook.dead_lettered".to_string(),
            severity: Severity::Error,
            actor_did: None,
            subject: Some(event.uri.to_string()),
            detail: serde_json::json!({
                "lexicon_id": event.lexicon_id,
                "action": event.action,
                "collection": event.collection,
                "error": last_error,
                "attempts": max_attempts,
            }),
        },
    )
    .await;
}

/// Execute a hook script once. Returns Ok(()) on success or Err(message) on failure.
async fn run_hook_once(event: &HookEvent<'_>) -> Result<(), String> {
    let lua = sandbox::create_sandbox().map_err(|e| format!("failed to create Lua VM: {e}"))?;

    let state_arc = Arc::new(event.state.clone());

    db_api::register_db_api(&lua, state_arc.clone())
        .map_err(|e| format!("failed to register db API: {e}"))?;

    http_api::register_http_api(&lua, state_arc)
        .map_err(|e| format!("failed to register http API: {e}"))?;

    context::set_hook_context(
        &lua,
        event.action,
        event.uri,
        event.did,
        event.collection,
        event.rkey,
        event.record,
    )
    .map_err(|e| format!("failed to set hook context: {e}"))?;

    lua.load(event.script)
        .exec()
        .map_err(|e| format!("script load failed: {e}"))?;

    let handle: mlua::Function = lua
        .globals()
        .get("handle")
        .map_err(|e| format!("script missing handle function: {e}"))?;

    handle
        .call_async::<mlua::Value>(())
        .await
        .map_err(|e| e.to_string())?;

    Ok(())
}
