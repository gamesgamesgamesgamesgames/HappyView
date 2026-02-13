use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use bytes::Bytes;

#[derive(Debug)]
pub enum AppError {
    Auth(String),
    BadRequest(String),
    Internal(String),
    NotFound(String),
    PdsError(StatusCode, Bytes),
}

impl std::fmt::Display for AppError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            AppError::Auth(msg) => write!(f, "auth error: {msg}"),
            AppError::BadRequest(msg) => write!(f, "bad request: {msg}"),
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
                    AppError::BadRequest(msg) => (StatusCode::BAD_REQUEST, msg.clone()),
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
    async fn internal_error_returns_500_and_hides_detail() {
        let (status, body) = response_parts(AppError::Internal("secret details".into())).await;
        assert_eq!(status, StatusCode::INTERNAL_SERVER_ERROR);
        assert_eq!(body["error"], "internal server error");
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
    }
}
