use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use bytes::Bytes;
use serde::Serialize;

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ScriptErrorType {
    Syntax,
    Runtime,
    Timeout,
    MissingHandle,
}

impl std::fmt::Display for ScriptErrorType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ScriptErrorType::Syntax => write!(f, "syntax"),
            ScriptErrorType::Runtime => write!(f, "runtime"),
            ScriptErrorType::Timeout => write!(f, "timeout"),
            ScriptErrorType::MissingHandle => write!(f, "missing_handle"),
        }
    }
}

/// Parse a Lua error message to extract a line number.
///
/// mlua errors look like:
/// - `[string "..."]:42: attempt to index a nil value`
/// - `runtime error: [string "..."]:10: bad argument`
///
/// Returns `(Some(line), cleaned_message)` or `(None, original_message)`.
pub fn parse_lua_line(raw: &str) -> (Option<u32>, String) {
    if let Some(bracket_pos) = raw.find("]:") {
        let after_bracket = &raw[bracket_pos + 2..];
        if let Some(colon_pos) = after_bracket.find(": ") {
            let line_str = &after_bracket[..colon_pos];
            if let Ok(line) = line_str.parse::<u32>() {
                let message = after_bracket[colon_pos + 2..].to_string();
                return (Some(line), message);
            }
        }
    }
    (None, raw.to_string())
}

#[derive(Debug)]
pub enum AppError {
    Auth(String),
    /// Auth failure with a DPoP nonce that the client should retry with.
    AuthDpopNonce(String),
    BadGateway(String),
    BadRequest(String),
    Forbidden(String),
    InsufficientPermissions(String),
    Internal(String),
    NotFound(String),
    PdsError(StatusCode, Bytes),
    ScriptError {
        error_type: ScriptErrorType,
        message: String,
        method: String,
        line: Option<u32>,
    },
}

impl std::fmt::Display for AppError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            AppError::Auth(msg) => write!(f, "auth error: {msg}"),
            AppError::AuthDpopNonce(nonce) => write!(f, "auth error: use_dpop_nonce ({nonce})"),
            AppError::BadGateway(msg) => write!(f, "bad gateway: {msg}"),
            AppError::BadRequest(msg) => write!(f, "bad request: {msg}"),
            AppError::Forbidden(msg) => write!(f, "forbidden: {msg}"),
            AppError::InsufficientPermissions(perm) => write!(f, "Missing permission: {perm}"),
            AppError::Internal(msg) => write!(f, "internal error: {msg}"),
            AppError::NotFound(msg) => write!(f, "not found: {msg}"),
            AppError::PdsError(status, _) => write!(f, "PDS error: {status}"),
            AppError::ScriptError {
                error_type,
                message,
                method,
                line,
            } => {
                if let Some(l) = line {
                    write!(
                        f,
                        "script {error_type} error in {method} at line {l}: {message}"
                    )
                } else {
                    write!(f, "script {error_type} error in {method}: {message}")
                }
            }
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
            AppError::AuthDpopNonce(nonce) => {
                let body = serde_json::json!({ "error": "use_dpop_nonce", "dpop_nonce": nonce });
                let mut response = (StatusCode::UNAUTHORIZED, axum::Json(body)).into_response();
                if let Ok(val) = axum::http::HeaderValue::from_str(&nonce) {
                    response.headers_mut().insert("dpop-nonce", val);
                }
                response
            }
            AppError::ScriptError {
                error_type,
                message,
                method,
                line,
            } => {
                let status = match &error_type {
                    ScriptErrorType::Timeout => StatusCode::REQUEST_TIMEOUT,
                    _ => StatusCode::INTERNAL_SERVER_ERROR,
                };
                tracing::error!(%method, ?error_type, ?line, "{message}");
                let body = serde_json::json!({
                    "error": "script_error",
                    "errorType": error_type,
                    "message": message,
                    "method": method,
                    "line": line,
                });
                (status, axum::Json(body)).into_response()
            }
            AppError::InsufficientPermissions(perm) => {
                let body = serde_json::json!({
                    "error": "InsufficientPermissions",
                    "message": format!("Missing permission: {perm}"),
                });
                (StatusCode::FORBIDDEN, axum::Json(body)).into_response()
            }
            other => {
                let (status, message) = match &other {
                    AppError::Auth(msg) => (StatusCode::UNAUTHORIZED, msg.clone()),
                    AppError::BadGateway(msg) => (StatusCode::BAD_GATEWAY, msg.clone()),
                    AppError::BadRequest(msg) => (StatusCode::BAD_REQUEST, msg.clone()),

                    AppError::Forbidden(msg) => (StatusCode::FORBIDDEN, msg.clone()),
                    AppError::Internal(msg) => {
                        tracing::error!("{msg}");
                        (StatusCode::INTERNAL_SERVER_ERROR, msg.clone())
                    }
                    AppError::NotFound(msg) => (StatusCode::NOT_FOUND, msg.clone()),
                    AppError::PdsError(..)
                    | AppError::AuthDpopNonce(..)
                    | AppError::InsufficientPermissions(..)
                    | AppError::ScriptError { .. } => unreachable!(),
                };

                let body = serde_json::json!({ "error": message });
                (status, axum::Json(body)).into_response()
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::response::IntoResponse;
    use http_body_util::BodyExt;

    async fn response_parts(err: AppError) -> (StatusCode, serde_json::Value) {
        let resp = err.into_response();
        let status = resp.status();
        let body = resp.into_body().collect().await.unwrap().to_bytes();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        (status, json)
    }

    #[tokio::test]
    async fn auth_error_returns_401() {
        let (status, body) = response_parts(AppError::Auth("bad token".into())).await;
        assert_eq!(status, StatusCode::UNAUTHORIZED);
        assert_eq!(body["error"], "bad token");
    }

    #[tokio::test]
    async fn bad_request_returns_400() {
        let (status, body) = response_parts(AppError::BadRequest("missing field".into())).await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
        assert_eq!(body["error"], "missing field");
    }

    #[tokio::test]
    async fn internal_error_returns_500_with_message() {
        let (status, body) = response_parts(AppError::Internal("secret details".into())).await;
        assert_eq!(status, StatusCode::INTERNAL_SERVER_ERROR);
        assert_eq!(body["error"], "secret details");
    }

    #[tokio::test]
    async fn script_error_returns_500_with_structured_body() {
        let (status, body) = response_parts(AppError::ScriptError {
            error_type: ScriptErrorType::Runtime,
            message: "attempt to index a nil value".into(),
            method: "games.gamesgamesgamesgames.search".into(),
            line: Some(42),
        })
        .await;
        assert_eq!(status, StatusCode::INTERNAL_SERVER_ERROR);
        assert_eq!(body["error"], "script_error");
        assert_eq!(body["errorType"], "runtime");
        assert_eq!(body["message"], "attempt to index a nil value");
        assert_eq!(body["method"], "games.gamesgamesgamesgames.search");
        assert_eq!(body["line"], 42);
    }

    #[tokio::test]
    async fn script_error_timeout_returns_408() {
        let (status, body) = response_parts(AppError::ScriptError {
            error_type: ScriptErrorType::Timeout,
            message: "script exceeded execution time limit".into(),
            method: "test.method".into(),
            line: None,
        })
        .await;
        assert_eq!(status, StatusCode::REQUEST_TIMEOUT);
        assert_eq!(body["error"], "script_error");
        assert_eq!(body["errorType"], "timeout");
        assert!(body["line"].is_null());
    }

    #[tokio::test]
    async fn script_error_syntax_returns_500() {
        let (status, body) = response_parts(AppError::ScriptError {
            error_type: ScriptErrorType::Syntax,
            message: "unexpected symbol near ')'".into(),
            method: "test.method".into(),
            line: Some(5),
        })
        .await;
        assert_eq!(status, StatusCode::INTERNAL_SERVER_ERROR);
        assert_eq!(body["error"], "script_error");
        assert_eq!(body["errorType"], "syntax");
        assert_eq!(body["line"], 5);
    }

    #[tokio::test]
    async fn not_found_returns_404() {
        let (status, body) = response_parts(AppError::NotFound("no such thing".into())).await;
        assert_eq!(status, StatusCode::NOT_FOUND);
        assert_eq!(body["error"], "no such thing");
    }

    #[tokio::test]
    async fn pds_error_preserves_status_and_body() {
        let raw_body = Bytes::from(r#"{"error":"upstream"}"#);
        let resp = AppError::PdsError(StatusCode::BAD_GATEWAY, raw_body.clone()).into_response();
        assert_eq!(resp.status(), StatusCode::BAD_GATEWAY);
        let body = resp.into_body().collect().await.unwrap().to_bytes();
        assert_eq!(body, raw_body);
    }

    #[test]
    fn parse_lua_line_extracts_line_number() {
        let (line, msg) = parse_lua_line("[string \"...\"]:42: attempt to index a nil value");
        assert_eq!(line, Some(42));
        assert_eq!(msg, "attempt to index a nil value");
    }

    #[test]
    fn parse_lua_line_no_line_number() {
        let (line, msg) = parse_lua_line("some other error");
        assert_eq!(line, None);
        assert_eq!(msg, "some other error");
    }

    #[test]
    fn parse_lua_line_runtime_error_prefix() {
        let (line, msg) = parse_lua_line("runtime error: [string \"...\"]:10: bad argument");
        assert_eq!(line, Some(10));
        assert_eq!(msg, "bad argument");
    }

    #[test]
    fn script_error_type_serializes() {
        assert_eq!(
            serde_json::to_string(&ScriptErrorType::Syntax).unwrap(),
            "\"syntax\""
        );
        assert_eq!(
            serde_json::to_string(&ScriptErrorType::Runtime).unwrap(),
            "\"runtime\""
        );
        assert_eq!(
            serde_json::to_string(&ScriptErrorType::Timeout).unwrap(),
            "\"timeout\""
        );
        assert_eq!(
            serde_json::to_string(&ScriptErrorType::MissingHandle).unwrap(),
            "\"missing_handle\""
        );
    }

    #[test]
    fn display_formats() {
        assert_eq!(AppError::Auth("x".into()).to_string(), "auth error: x");
        assert_eq!(
            AppError::BadRequest("y".into()).to_string(),
            "bad request: y"
        );
        assert_eq!(
            AppError::Internal("z".into()).to_string(),
            "internal error: z"
        );
        assert_eq!(AppError::NotFound("w".into()).to_string(), "not found: w");
        assert_eq!(
            AppError::PdsError(StatusCode::BAD_GATEWAY, Bytes::new()).to_string(),
            "PDS error: 502 Bad Gateway"
        );
        assert_eq!(
            AppError::ScriptError {
                error_type: ScriptErrorType::Runtime,
                message: "oops".into(),
                method: "test.method".into(),
                line: Some(5),
            }
            .to_string(),
            "script runtime error in test.method at line 5: oops"
        );
    }
}
