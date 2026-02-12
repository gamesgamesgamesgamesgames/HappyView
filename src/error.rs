use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use bytes::Bytes;

#[derive(Debug)]
pub enum AppError {
    Auth(String),
    Internal(String),
    NotFound(String),
    PdsError(StatusCode, Bytes),
}

impl std::fmt::Display for AppError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            AppError::Auth(msg) => write!(f, "auth error: {msg}"),
            AppError::Internal(msg) => write!(f, "internal error: {msg}"),
            AppError::NotFound(msg) => write!(f, "not found: {msg}"),
            AppError::PdsError(status, _) => write!(f, "PDS error: {status}"),
        }
    }
}

impl IntoResponse for AppError {
    fn into_response(self) -> Response {
        match self {
            AppError::PdsError(status, body) => (
                status,
                [(axum::http::header::CONTENT_TYPE, "application/json")],
                body,
            )
                .into_response(),
            other => {
                let (status, message) = match &other {
                    AppError::Auth(msg) => (StatusCode::UNAUTHORIZED, msg.clone()),
                    AppError::Internal(msg) => {
                        tracing::error!("{msg}");
                        (
                            StatusCode::INTERNAL_SERVER_ERROR,
                            "internal server error".into(),
                        )
                    }
                    AppError::NotFound(msg) => (StatusCode::NOT_FOUND, msg.clone()),
                    AppError::PdsError(..) => unreachable!(),
                };

                let body = serde_json::json!({ "error": message });
                (status, axum::Json(body)).into_response()
            }
        }
    }
}
