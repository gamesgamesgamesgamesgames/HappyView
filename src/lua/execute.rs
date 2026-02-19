use axum::Json;
use axum::response::{IntoResponse, Response};
use mlua::LuaSerdeExt;
use serde_json::Value;
use std::collections::HashMap;
use std::sync::Arc;

use crate::AppState;
use crate::auth::Claims;
use crate::error::AppError;
use crate::lexicon::ParsedLexicon;
use crate::repo;

use super::context;
use super::db_api;
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
    let collection = lexicon.target_collection.as_deref().unwrap_or_default();

    let session = repo::get_atp_session(state, claims.token()).await?;

    let lua = sandbox::create_sandbox()
        .map_err(|e| AppError::Internal(format!("failed to create Lua VM: {e}")))?;

    let state_arc = Arc::new(state.clone());
    let claims_arc = Arc::new(claims.clone());
    let session_arc = Arc::new(session);

    db_api::register_db_api(&lua, state_arc.clone())
        .map_err(|e| AppError::Internal(format!("failed to register db API: {e}")))?;

    record::register_record_api(&lua, state_arc, claims_arc, session_arc)
        .map_err(|e| AppError::Internal(format!("failed to register Record API: {e}")))?;

    context::set_procedure_context(&lua, method, input, claims.did(), collection)
        .map_err(|e| AppError::Internal(format!("failed to set context: {e}")))?;

    lua.load(script).exec().map_err(|e| {
        tracing::error!(method, error = %e, "lua script load failed");
        AppError::Internal("script execution failed".into())
    })?;

    let handle: mlua::Function = lua.globals().get("handle").map_err(|e| {
        tracing::error!(method, error = %e, "lua script missing handle function");
        AppError::Internal("script execution failed".into())
    })?;

    let result: mlua::Value = handle.call_async(()).await.map_err(|e| {
        let msg = e.to_string();
        tracing::error!(method, error = %msg, "lua script execution failed");
        if msg.contains("execution limit") {
            AppError::Internal("script exceeded execution time limit".into())
        } else {
            AppError::Internal("script execution failed".into())
        }
    })?;

    let json_value: Value = lua.from_value(result).map_err(|e| {
        tracing::error!(method, error = %e, "failed to convert lua result to JSON");
        AppError::Internal("script execution failed".into())
    })?;

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
    let collection = lexicon.target_collection.as_deref().unwrap_or_default();

    let lua = sandbox::create_sandbox()
        .map_err(|e| AppError::Internal(format!("failed to create Lua VM: {e}")))?;

    let state_arc = Arc::new(state.clone());

    db_api::register_db_api(&lua, state_arc)
        .map_err(|e| AppError::Internal(format!("failed to register db API: {e}")))?;

    context::set_query_context(&lua, method, params, collection)
        .map_err(|e| AppError::Internal(format!("failed to set context: {e}")))?;

    lua.load(script).exec().map_err(|e| {
        tracing::error!(method, error = %e, "lua script load failed");
        AppError::Internal("script execution failed".into())
    })?;

    let handle: mlua::Function = lua.globals().get("handle").map_err(|e| {
        tracing::error!(method, error = %e, "lua script missing handle function");
        AppError::Internal("script execution failed".into())
    })?;

    let result: mlua::Value = handle.call_async(()).await.map_err(|e| {
        let msg = e.to_string();
        tracing::error!(method, error = %msg, "lua script execution failed");
        if msg.contains("execution limit") {
            AppError::Internal("script exceeded execution time limit".into())
        } else {
            AppError::Internal("script execution failed".into())
        }
    })?;

    let json_value: Value = lua.from_value(result).map_err(|e| {
        tracing::error!(method, error = %e, "failed to convert lua result to JSON");
        AppError::Internal("script execution failed".into())
    })?;

    Ok(Json(json_value).into_response())
}
