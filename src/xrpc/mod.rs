mod procedure;
mod query;

use axum::Json;
use axum::extract::{Path, Query, State};
use axum::response::Response;
use std::collections::HashMap;

use crate::AppState;
use crate::auth::Claims;
use crate::error::AppError;
use crate::lexicon::LexiconType;

/// Catch-all GET handler for XRPC queries.
pub async fn xrpc_get(
    State(state): State<AppState>,
    Path(method): Path<String>,
    Query(params): Query<HashMap<String, String>>,
) -> Result<Response, AppError> {
    let lexicon = state
        .lexicons
        .get(&method)
        .await
        .ok_or_else(|| AppError::BadRequest(format!("method not found: {method}")))?;

    if lexicon.lexicon_type != LexiconType::Query {
        return Err(AppError::BadRequest(format!(
            "{method} is not a query endpoint"
        )));
    }

    query::handle_query(&state, &method, &params, &lexicon).await
}

/// Catch-all POST handler for XRPC procedures.
pub async fn xrpc_post(
    State(state): State<AppState>,
    Path(method): Path<String>,
    claims: Claims,
    Json(body): Json<serde_json::Value>,
) -> Result<Response, AppError> {
    let lexicon = state
        .lexicons
        .get(&method)
        .await
        .ok_or_else(|| AppError::BadRequest(format!("method not found: {method}")))?;

    if lexicon.lexicon_type != LexiconType::Procedure {
        return Err(AppError::BadRequest(format!(
            "{method} is not a procedure endpoint"
        )));
    }

    procedure::handle_procedure(&state, &method, &claims, &body, &lexicon).await
}
