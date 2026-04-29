use axum::Json;
use axum::response::{IntoResponse, Response};
use mlua::LuaSerdeExt;
use serde_json::Value;
use std::collections::HashMap;
use std::sync::Arc;
use std::time::Instant;

use crate::AppState;
use crate::auth::Claims;
use crate::db::{DatabaseBackend, adapt_sql, now_rfc3339};
use crate::error::{AppError, ScriptErrorType, parse_lua_line};
use crate::event_log::{EventLog, Severity, log_event};
use crate::lexicon::ParsedLexicon;
use crate::repo;

use super::atproto_api;
use super::context;
use super::db_api;
use super::http_api;
use super::record;
use super::sandbox;

/// Load all script variables from the database as a key-value map.
async fn load_env_vars(db: &sqlx::AnyPool, backend: DatabaseBackend) -> HashMap<String, String> {
    let sql = adapt_sql("SELECT key, value FROM script_variables", backend);
    sqlx::query_as::<_, (String, String)>(&sql)
        .fetch_all(db)
        .await
        .unwrap_or_default()
        .into_iter()
        .collect()
}

/// Execute a Lua script for a procedure endpoint.
pub async fn execute_procedure_script(
    state: &AppState,
    method: &str,
    claims: &Claims,
    input: &Value,
    params: &std::collections::HashMap<String, Value>,
    lexicon: &ParsedLexicon,
    script: &str,
) -> Result<Response, AppError> {
    let start = Instant::now();
    let backend = state.db_backend;
    let span = tracing::info_span!(
        "script.execute",
        method = method,
        script_type = "procedure",
        caller_did = %claims.did(),
    );
    span.in_scope(|| tracing::info!("script execution started"));
    let collection = lexicon.target_collection.as_deref().unwrap_or_default();

    // Capture script source and input for error logging before anything is consumed.
    let script_source = script.to_string();
    let input_json = input.clone();

    let pds_auth = if let Some(client_key) = claims.client_key() {
        let encryption_key = state
            .config
            .token_encryption_key
            .as_ref()
            .ok_or_else(|| AppError::Internal("TOKEN_ENCRYPTION_KEY not configured".into()))?;
        let api_client_id = match repo::get_dpop_client_id(state, client_key).await {
            Ok(id) => id,
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
                            "duration_ms": start.elapsed().as_millis() as u64,
                        }),
                    },
                    backend,
                )
                .await;
                return Err(e);
            }
        };
        repo::PdsAuth::Dpop {
            api_client_id,
            encryption_key: *encryption_key,
        }
    } else {
        match repo::get_oauth_session(state, claims.did()).await {
            Ok(s) => repo::PdsAuth::OAuth(Arc::new(s)),
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
                            "duration_ms": start.elapsed().as_millis() as u64,
                        }),
                    },
                    backend,
                )
                .await;
                return Err(e);
            }
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
                        "duration_ms": start.elapsed().as_millis() as u64,
                    }),
                },
                backend,
            )
            .await;
            return Err(AppError::Internal(error_message));
        }
    };

    let state_arc = Arc::new(state.clone());
    let claims_arc = Arc::new(claims.clone());
    let pds_auth_arc = Arc::new(pds_auth);

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
                    "duration_ms": start.elapsed().as_millis() as u64,
                }),
            },
            backend,
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
                    "duration_ms": start.elapsed().as_millis() as u64,
                }),
            },
            backend,
        )
        .await;
        return Err(AppError::Internal(error_message));
    }

    if let Err(e) =
        super::xrpc_api::register_xrpc_api(&lua, state_arc.clone(), Some(claims.did().to_string()))
    {
        let error_message = format!("failed to register xrpc API: {e}");
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
                    "duration_ms": start.elapsed().as_millis() as u64,
                }),
            },
            backend,
        )
        .await;
        return Err(AppError::Internal(error_message));
    }

    if let Err(e) = atproto_api::register_atproto_api(&lua, state_arc.clone(), Some(claims.did())) {
        let error_message = format!("failed to register atproto API: {e}");
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
                    "duration_ms": start.elapsed().as_millis() as u64,
                }),
            },
            backend,
        )
        .await;
        return Err(AppError::Internal(error_message));
    }

    if let Err(e) = record::register_record_api(&lua, state_arc, claims_arc, pds_auth_arc) {
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
                    "duration_ms": start.elapsed().as_millis() as u64,
                }),
            },
            backend,
        )
        .await;
        return Err(AppError::Internal(error_message));
    }

    if let Err(e) =
        context::set_procedure_context(&lua, method, input, params, claims.did(), collection)
    {
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
                    "duration_ms": start.elapsed().as_millis() as u64,
                }),
            },
            backend,
        )
        .await;
        return Err(AppError::Internal(error_message));
    }

    if let Err(e) = context::set_env_context(&lua, &load_env_vars(&state.db, backend).await) {
        let error_message = format!("failed to set env context: {e}");
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
                    "duration_ms": start.elapsed().as_millis() as u64,
                }),
            },
            backend,
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
                    "duration_ms": start.elapsed().as_millis() as u64,
                }),
            },
            backend,
        )
        .await;
        let (line, clean_msg) = parse_lua_line(&error_message);
        return Err(AppError::ScriptError {
            error_type: ScriptErrorType::Syntax,
            message: clean_msg,
            method: method.to_string(),
            line,
        });
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
                        "duration_ms": start.elapsed().as_millis() as u64,
                    }),
                },
                backend,
            )
            .await;
            return Err(AppError::ScriptError {
                error_type: ScriptErrorType::MissingHandle,
                message: "script does not define a handle() function".to_string(),
                method: method.to_string(),
                line: None,
            });
        }
    };

    let result: mlua::Value = match handle.call_async(()).await {
        Ok(r) => r,
        Err(e) => {
            let msg = e.to_string();
            tracing::error!(method, error = %msg, "lua script execution failed");
            let (line, clean_msg) = parse_lua_line(&msg);
            let app_error = if msg.contains("execution limit") {
                AppError::ScriptError {
                    error_type: ScriptErrorType::Timeout,
                    message: "script exceeded execution time limit".to_string(),
                    method: method.to_string(),
                    line,
                }
            } else {
                AppError::ScriptError {
                    error_type: ScriptErrorType::Runtime,
                    message: clean_msg,
                    method: method.to_string(),
                    line,
                }
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
                        "duration_ms": start.elapsed().as_millis() as u64,
                    }),
                },
                backend,
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
                        "duration_ms": start.elapsed().as_millis() as u64,
                    }),
                },
                backend,
            )
            .await;
            return Err(AppError::ScriptError {
                error_type: ScriptErrorType::Runtime,
                message: error_message,
                method: method.to_string(),
                line: None,
            });
        }
    };

    span.in_scope(|| {
        tracing::info!(
            duration_ms = start.elapsed().as_millis() as u64,
            "script execution completed"
        );
    });
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
                "response_size": json_value.to_string().len(),
                "input": input_json,
                "response": json_value,
            }),
        },
        backend,
    )
    .await;

    Ok(Json(json_value).into_response())
}

/// Execute a Lua script for a query endpoint.
pub async fn execute_query_script(
    state: &AppState,
    method: &str,
    params: &HashMap<String, serde_json::Value>,
    lexicon: &ParsedLexicon,
    script: &str,
    claims: Option<&Claims>,
) -> Result<Response, AppError> {
    let start = Instant::now();
    let backend = state.db_backend;
    let span = tracing::info_span!("script.execute", method = method, script_type = "query",);
    span.in_scope(|| tracing::info!("script execution started"));
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
                        "duration_ms": start.elapsed().as_millis() as u64,
                    }),
                },
                backend,
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
                    "duration_ms": start.elapsed().as_millis() as u64,
                }),
            },
            backend,
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
                actor_did: None,
                subject: Some(method.to_string()),
                detail: serde_json::json!({
                    "error": error_message,
                    "script_source": script_source,
                    "method": method,
                    "duration_ms": start.elapsed().as_millis() as u64,
                }),
            },
            backend,
        )
        .await;
        return Err(AppError::Internal(error_message));
    }

    if let Err(e) = super::xrpc_api::register_xrpc_api(
        &lua,
        state_arc.clone(),
        claims.map(|c| c.did().to_string()),
    ) {
        let error_message = format!("failed to register xrpc API: {e}");
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
                    "duration_ms": start.elapsed().as_millis() as u64,
                }),
            },
            backend,
        )
        .await;
        return Err(AppError::Internal(error_message));
    }

    if let Err(e) = atproto_api::register_atproto_api(&lua, state_arc, claims.map(|c| c.did())) {
        let error_message = format!("failed to register atproto API: {e}");
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
                    "duration_ms": start.elapsed().as_millis() as u64,
                }),
            },
            backend,
        )
        .await;
        return Err(AppError::Internal(error_message));
    }

    if let Err(e) =
        context::set_query_context(&lua, method, params, collection, claims.map(|c| c.did()))
    {
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
                    "duration_ms": start.elapsed().as_millis() as u64,
                }),
            },
            backend,
        )
        .await;
        return Err(AppError::Internal(error_message));
    }

    if let Err(e) = context::set_env_context(&lua, &load_env_vars(&state.db, backend).await) {
        let error_message = format!("failed to set env context: {e}");
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
                    "duration_ms": start.elapsed().as_millis() as u64,
                }),
            },
            backend,
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
                    "duration_ms": start.elapsed().as_millis() as u64,
                }),
            },
            backend,
        )
        .await;
        let (line, clean_msg) = parse_lua_line(&error_message);
        return Err(AppError::ScriptError {
            error_type: ScriptErrorType::Syntax,
            message: clean_msg,
            method: method.to_string(),
            line,
        });
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
                        "duration_ms": start.elapsed().as_millis() as u64,
                    }),
                },
                backend,
            )
            .await;
            return Err(AppError::ScriptError {
                error_type: ScriptErrorType::MissingHandle,
                message: "script does not define a handle() function".to_string(),
                method: method.to_string(),
                line: None,
            });
        }
    };

    let result: mlua::Value = match handle.call_async(()).await {
        Ok(r) => r,
        Err(e) => {
            let msg = e.to_string();
            tracing::error!(method, error = %msg, "lua script execution failed");
            let (line, clean_msg) = parse_lua_line(&msg);
            let app_error = if msg.contains("execution limit") {
                AppError::ScriptError {
                    error_type: ScriptErrorType::Timeout,
                    message: "script exceeded execution time limit".to_string(),
                    method: method.to_string(),
                    line,
                }
            } else {
                AppError::ScriptError {
                    error_type: ScriptErrorType::Runtime,
                    message: clean_msg,
                    method: method.to_string(),
                    line,
                }
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
                        "duration_ms": start.elapsed().as_millis() as u64,
                    }),
                },
                backend,
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
                        "duration_ms": start.elapsed().as_millis() as u64,
                    }),
                },
                backend,
            )
            .await;
            return Err(AppError::ScriptError {
                error_type: ScriptErrorType::Runtime,
                message: error_message,
                method: method.to_string(),
                line: None,
            });
        }
    };

    span.in_scope(|| {
        tracing::info!(
            duration_ms = start.elapsed().as_millis() as u64,
            "script execution completed"
        );
    });
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
                "response_size": json_value.to_string().len(),
                "params": params,
                "response": json_value,
            }),
        },
        backend,
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
/// Runs **before** the record is indexed. The return value determines what
/// gets stored:
/// - `None` → skip the DB operation entirely
/// - `Some(value)` → use that value for the insert/update
///
/// Retries up to 3 times with exponential backoff (1s, 2s, 4s).
/// On final failure, dead-letters the event and returns `Some(original_record)`
/// (fail-open so indexing is not permanently blocked).
pub async fn execute_hook_script(event: &HookEvent<'_>) -> Option<Value> {
    let max_attempts: i32 = 4; // 1 initial + 3 retries
    let mut last_error = String::new();
    let backend = event.state.db_backend;

    for attempt in 0..max_attempts {
        if attempt > 0 {
            let delay = std::time::Duration::from_secs(1 << (attempt - 1)); // 1s, 2s, 4s
            tokio::time::sleep(delay).await;
        }

        match run_hook_once(event).await {
            Ok(hook_result) => {
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
                    backend,
                )
                .await;
                return hook_result;
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

    // All retries exhausted — dead-letter the event and fail-open with the
    // original record so indexing is not permanently blocked.
    tracing::error!(
        uri = event.uri,
        lexicon_id = event.lexicon_id,
        "hook dead-lettered after {max_attempts} attempts"
    );

    let record_str = event
        .record
        .map(|r| serde_json::to_string(r).unwrap_or_default());
    let dead_letter_sql = adapt_sql(
        r#"
        INSERT INTO dead_letter_hooks (lexicon_id, uri, did, collection, rkey, action, record, error, attempts, created_at)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        "#,
        backend,
    );
    if let Err(e) = sqlx::query(&dead_letter_sql)
        .bind(event.lexicon_id)
        .bind(event.uri)
        .bind(event.did)
        .bind(event.collection)
        .bind(event.rkey)
        .bind(event.action)
        .bind(&record_str)
        .bind(&last_error)
        .bind(max_attempts)
        .bind(now_rfc3339())
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
        backend,
    )
    .await;

    // Fail-open: return the original record so indexing proceeds.
    event.record.cloned()
}

/// Execute a hook script once.
///
/// Returns `Ok(None)` when `handle()` returns nil (meaning "skip indexing"),
/// `Ok(Some(value))` when it returns a table (use that as the record), or
/// `Ok(Some(original))` for other non-nil types.
pub async fn run_hook_once(event: &HookEvent<'_>) -> Result<Option<Value>, String> {
    let lua = sandbox::create_sandbox().map_err(|e| format!("failed to create Lua VM: {e}"))?;
    let backend = event.state.db_backend;

    let state_arc = Arc::new(event.state.clone());

    db_api::register_db_api(&lua, state_arc.clone())
        .map_err(|e| format!("failed to register db API: {e}"))?;

    http_api::register_http_api(&lua, state_arc.clone())
        .map_err(|e| format!("failed to register http API: {e}"))?;

    super::xrpc_api::register_xrpc_api(&lua, state_arc.clone(), Some(event.did.to_string()))
        .map_err(|e| format!("failed to register xrpc API: {e}"))?;

    atproto_api::register_atproto_api(&lua, state_arc, None)
        .map_err(|e| format!("failed to register atproto API: {e}"))?;

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

    context::set_env_context(&lua, &load_env_vars(&event.state.db, backend).await)
        .map_err(|e| format!("failed to set env context: {e}"))?;

    lua.load(event.script)
        .exec()
        .map_err(|e| format!("script load failed: {e}"))?;

    let handle: mlua::Function = lua
        .globals()
        .get("handle")
        .map_err(|e| format!("script missing handle function: {e}"))?;

    let result: mlua::Value = handle
        .call_async::<mlua::Value>(())
        .await
        .map_err(|e| e.to_string())?;

    match result {
        mlua::Value::Nil => Ok(None),
        mlua::Value::Table(_) => {
            let json_value: Value = lua
                .from_value(result)
                .map_err(|e| format!("failed to convert lua table to JSON: {e}"))?;
            Ok(Some(json_value))
        }
        _ => {
            // Non-nil, non-table return — proceed with the original record.
            Ok(event.record.cloned())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::Config;
    use crate::db::DatabaseBackend;
    use crate::lexicon::LexiconRegistry;
    use serde_json::json;
    use tokio::sync::watch;

    fn test_state() -> AppState {
        let config = Config {
            host: "127.0.0.1".into(),
            port: 3000,
            database_url: String::new(),
            database_backend: crate::db::DatabaseBackend::Sqlite,
            public_url: String::new(),
            session_secret: "test-secret".into(),
            jetstream_url: String::new(),
            relay_url: String::new(),
            plc_url: String::new(),
            static_dir: String::new(),
            event_log_retention_days: 30,
            app_name: None,
            logo_uri: None,
            tos_uri: None,
            policy_uri: None,
            token_encryption_key: None,
            default_rate_limit_capacity: 100,
            default_rate_limit_refill_rate: 2.0,
        };
        let (tx, _) = watch::channel(vec![]);
        let (labeler_tx, _) = watch::channel(());
        sqlx::any::install_default_drivers();
        let test_db = sqlx::AnyPool::connect_lazy("sqlite::memory:").unwrap();
        let atrium_http = std::sync::Arc::new(atrium_oauth::DefaultHttpClient::default());
        let did_resolver = atrium_identity::did::CommonDidResolver::new(
            atrium_identity::did::CommonDidResolverConfig {
                plc_directory_url: "https://plc.directory".into(),
                http_client: std::sync::Arc::clone(&atrium_http),
            },
        );
        let handle_resolver = atrium_identity::handle::AtprotoHandleResolver::new(
            atrium_identity::handle::AtprotoHandleResolverConfig {
                dns_txt_resolver: crate::dns::NativeDnsResolver::new(),
                http_client: atrium_http,
            },
        );
        let oauth = atrium_oauth::OAuthClient::new(atrium_oauth::OAuthClientConfig {
            client_metadata: atrium_oauth::AtprotoLocalhostClientMetadata {
                redirect_uris: Some(vec!["http://127.0.0.1:0/auth/callback".into()]),
                scopes: Some(vec![atrium_oauth::Scope::Known(
                    atrium_oauth::KnownScope::Atproto,
                )]),
            },
            keys: None,
            state_store: crate::auth::oauth_store::DbStateStore::new(
                test_db.clone(),
                crate::db::DatabaseBackend::Sqlite,
            ),
            session_store: crate::auth::oauth_store::DbSessionStore::new(
                test_db.clone(),
                crate::db::DatabaseBackend::Sqlite,
            ),
            resolver: atrium_oauth::OAuthResolverConfig {
                did_resolver,
                handle_resolver,
                authorization_server_metadata: Default::default(),
                protected_resource_metadata: Default::default(),
            },
        })
        .expect("Failed to create test OAuth client");
        AppState {
            config,
            http: reqwest::Client::new(),
            db: test_db.clone(),
            db_backend: DatabaseBackend::Sqlite,
            domain_cache: crate::domain::DomainCache::new(),
            lexicons: LexiconRegistry::new(),
            collections_tx: tx,
            labeler_subscriptions_tx: labeler_tx,
            rate_limiter: crate::rate_limit::RateLimiter::new(
                crate::rate_limit::RateLimitDefaults {
                    query_cost: 1,
                    procedure_cost: 1,
                    proxy_cost: 1,
                },
            ),
            oauth: std::sync::Arc::new(crate::auth::OAuthClientRegistry::new(std::sync::Arc::new(
                oauth,
            ))),
            oauth_state_store: crate::auth::oauth_store::DbStateStore::new(
                test_db.clone(),
                crate::db::DatabaseBackend::Sqlite,
            ),
            cookie_key: axum_extra::extract::cookie::Key::derive_from(
                b"test-secret-for-tests-only-not-production",
            ),
            plugin_registry: std::sync::Arc::new(crate::plugin::PluginRegistry::new()),
            wasm_runtime: std::sync::Arc::new(
                crate::plugin::WasmRuntime::new().expect("wasm runtime"),
            ),
            attestation_signer: None,
            official_registry: std::sync::Arc::new(tokio::sync::RwLock::new(
                crate::plugin::official_registry::OfficialRegistryState::default(),
            )),
            official_registry_config: crate::plugin::official_registry::RegistryConfig::production(
            ),
            proxy_config: std::sync::Arc::new(arc_swap::ArcSwap::new(std::sync::Arc::new(
                crate::proxy_config::ProxyConfig::default(),
            ))),
        }
    }

    fn make_event<'a>(
        state: &'a AppState,
        script: &'a str,
        action: &'a str,
        record: Option<&'a Value>,
    ) -> HookEvent<'a> {
        HookEvent {
            state,
            lexicon_id: "test.lexicon",
            script,
            action,
            uri: "at://did:plc:test/test.collection/rkey1",
            did: "did:plc:test",
            collection: "test.collection",
            rkey: "rkey1",
            record,
        }
    }

    #[tokio::test]
    async fn hook_runs_simple_script() {
        let state = test_state();
        let event = make_event(&state, "function handle() end", "create", None);
        let result = run_hook_once(&event).await;
        assert!(result.is_ok(), "expected Ok, got: {:?}", result);
        // handle() returns nil implicitly, so result should be None (skip).
        assert!(result.unwrap().is_none());
    }

    #[tokio::test]
    async fn hook_returns_nil_to_skip() {
        let state = test_state();
        let record = json!({"name": "Test"});
        let event = make_event(
            &state,
            "function handle() return nil end",
            "create",
            Some(&record),
        );
        let result = run_hook_once(&event).await;
        assert!(result.is_ok(), "expected Ok, got: {:?}", result);
        assert!(result.unwrap().is_none(), "nil return should produce None");
    }

    #[tokio::test]
    async fn hook_returns_modified_record() {
        let state = test_state();
        let record = json!({"name": "Original"});
        let script = r#"
            function handle()
                return { name = "Modified", extra = true }
            end
        "#;
        let event = make_event(&state, script, "create", Some(&record));
        let result = run_hook_once(&event).await;
        assert!(result.is_ok(), "expected Ok, got: {:?}", result);
        let value = result.unwrap();
        assert!(value.is_some(), "table return should produce Some");
        let v = value.unwrap();
        assert_eq!(v["name"], "Modified");
        assert_eq!(v["extra"], true);
    }

    #[tokio::test]
    async fn hook_fails_on_missing_handle() {
        let state = test_state();
        let event = make_event(&state, "function other() end", "create", None);
        let result = run_hook_once(&event).await;
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(err.contains("handle"), "expected handle error, got: {err}");
    }

    #[tokio::test]
    async fn hook_fails_on_syntax_error() {
        let state = test_state();
        let event = make_event(&state, "function handle(", "create", None);
        let result = run_hook_once(&event).await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn hook_has_access_to_context_globals() {
        let state = test_state();
        let script = r#"
            function handle()
                if action ~= "create" then error("wrong action: " .. tostring(action)) end
                if uri ~= "at://did:plc:test/test.collection/rkey1" then error("wrong uri") end
                if did ~= "did:plc:test" then error("wrong did") end
                if collection ~= "test.collection" then error("wrong collection") end
                if rkey ~= "rkey1" then error("wrong rkey") end
            end
        "#;
        let event = make_event(&state, script, "create", None);
        let result = run_hook_once(&event).await;
        assert!(result.is_ok(), "expected Ok, got: {:?}", result);
    }

    #[tokio::test]
    async fn hook_has_access_to_record() {
        let state = test_state();
        let record = json!({"name": "Test"});
        let script = r#"
            function handle()
                if record.name ~= "Test" then error("wrong name: " .. tostring(record.name)) end
            end
        "#;
        let event = make_event(&state, script, "create", Some(&record));
        let result = run_hook_once(&event).await;
        assert!(result.is_ok(), "expected Ok, got: {:?}", result);
    }

    #[tokio::test]
    async fn hook_record_nil_on_delete() {
        let state = test_state();
        let script = r#"
            function handle()
                if record ~= nil then error("expected nil record") end
            end
        "#;
        let event = make_event(&state, script, "delete", None);
        let result = run_hook_once(&event).await;
        assert!(result.is_ok(), "expected Ok, got: {:?}", result);
    }
}
