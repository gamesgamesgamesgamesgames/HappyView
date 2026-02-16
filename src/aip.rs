use axum::body::Body;
use axum::extract::{Path, State};
use axum::http::{HeaderMap, Method, StatusCode, Uri};
use axum::response::{IntoResponse, Response};

use crate::AppState;

/// Reverse-proxy requests from `/aip/*` to the configured AIP server.
pub async fn aip_proxy(
    State(state): State<AppState>,
    method: Method,
    Path(path): Path<String>,
    uri: Uri,
    headers: HeaderMap,
    body: Body,
) -> impl IntoResponse {
    let query = uri.query().map(|q| format!("?{q}")).unwrap_or_default();
    let upstream_url = format!("{}/{path}{query}", state.config.aip_url);

    let mut req = state.http.request(method.clone(), &upstream_url);

    // Copy relevant request headers
    for name in ["content-type", "authorization", "dpop", "accept"] {
        if let Some(val) = headers.get(name) {
            req = req.header(name, val);
        }
    }

    // Attach body for non-GET requests
    if method != Method::GET {
        let bytes = match axum::body::to_bytes(body, 10 * 1024 * 1024).await {
            Ok(b) => b,
            Err(_) => {
                return Response::builder()
                    .status(StatusCode::BAD_REQUEST)
                    .body(Body::from("request body too large"))
                    .unwrap();
            }
        };
        req = req.body(bytes);
    }

    let upstream_resp = match req.send().await {
        Ok(r) => r,
        Err(e) => {
            tracing::error!("AIP proxy error: {e:#}");
            return Response::builder()
                .status(StatusCode::BAD_GATEWAY)
                .body(Body::from("upstream request failed"))
                .unwrap();
        }
    };

    let status = upstream_resp.status();
    let mut resp_headers = HeaderMap::new();

    // Copy relevant response headers
    for name in [
        "content-type",
        "dpop-nonce",
        "www-authenticate",
        "cache-control",
    ] {
        if let Some(val) = upstream_resp.headers().get(name) {
            resp_headers.insert(
                name.parse::<axum::http::header::HeaderName>().unwrap(),
                val.clone(),
            );
        }
    }

    let bytes = match upstream_resp.bytes().await {
        Ok(b) => b,
        Err(e) => {
            tracing::error!("AIP proxy read error: {e}");
            return Response::builder()
                .status(StatusCode::BAD_GATEWAY)
                .body(Body::from("failed to read upstream response"))
                .unwrap();
        }
    };

    let mut response = Response::new(Body::from(bytes));
    *response.status_mut() = status;
    *response.headers_mut() = resp_headers;
    response
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::Router;
    use axum::body::to_bytes;
    use axum::extract::Request;
    use axum::routing::{get, post};
    use tokio::sync::watch;
    use tower::ServiceExt;

    fn test_state(aip_url: &str) -> AppState {
        let config = crate::config::Config {
            host: "127.0.0.1".into(),
            port: 3000,
            database_url: String::new(),
            aip_url: aip_url.into(),
            aip_public_url: String::new(),
            tap_url: String::new(),
            tap_admin_password: None,
            relay_url: String::new(),
            plc_url: String::new(),
            static_dir: String::new(),
        };
        let (tx, _) = watch::channel(vec![]);
        AppState {
            config,
            http: reqwest::Client::new(),
            db: sqlx::PgPool::connect_lazy("postgres://localhost/fake").unwrap(),
            lexicons: crate::lexicon::LexiconRegistry::new(),
            collections_tx: tx,
        }
    }

    #[tokio::test]
    async fn proxy_forwards_get_request() {
        let mock = wiremock::MockServer::start().await;
        wiremock::Mock::given(wiremock::matchers::method("GET"))
            .and(wiremock::matchers::path("/oauth/authorize"))
            .respond_with(
                wiremock::ResponseTemplate::new(200)
                    .set_body_string("ok")
                    .insert_header("content-type", "text/plain")
                    .insert_header("dpop-nonce", "test-nonce"),
            )
            .mount(&mock)
            .await;

        let state = test_state(&mock.uri());
        let app = Router::new()
            .route("/aip/{*path}", get(aip_proxy))
            .with_state(state);

        let req = Request::builder()
            .method("GET")
            .uri("/aip/oauth/authorize")
            .body(Body::empty())
            .unwrap();

        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        assert_eq!(resp.headers().get("dpop-nonce").unwrap(), "test-nonce");
        let body = to_bytes(resp.into_body(), usize::MAX).await.unwrap();
        assert_eq!(&body[..], b"ok");
    }

    #[tokio::test]
    async fn proxy_forwards_post_with_body() {
        let mock = wiremock::MockServer::start().await;
        wiremock::Mock::given(wiremock::matchers::method("POST"))
            .and(wiremock::matchers::path("/oauth/token"))
            .respond_with(
                wiremock::ResponseTemplate::new(200)
                    .set_body_json(serde_json::json!({"access_token": "tok"}))
                    .insert_header("content-type", "application/json"),
            )
            .mount(&mock)
            .await;

        let state = test_state(&mock.uri());
        let app = Router::new()
            .route("/aip/{*path}", post(aip_proxy))
            .with_state(state);

        let req = Request::builder()
            .method("POST")
            .uri("/aip/oauth/token")
            .header("content-type", "application/x-www-form-urlencoded")
            .body(Body::from("grant_type=authorization_code"))
            .unwrap();

        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        assert_eq!(
            resp.headers().get("content-type").unwrap(),
            "application/json"
        );
    }

    #[tokio::test]
    async fn proxy_forwards_query_string() {
        let mock = wiremock::MockServer::start().await;
        wiremock::Mock::given(wiremock::matchers::method("GET"))
            .and(wiremock::matchers::path("/oauth/authorize"))
            .and(wiremock::matchers::query_param("client_id", "abc"))
            .respond_with(wiremock::ResponseTemplate::new(200).set_body_string("found"))
            .mount(&mock)
            .await;

        let state = test_state(&mock.uri());
        let app = Router::new()
            .route("/aip/{*path}", get(aip_proxy))
            .with_state(state);

        let req = Request::builder()
            .method("GET")
            .uri("/aip/oauth/authorize?client_id=abc")
            .body(Body::empty())
            .unwrap();

        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let body = to_bytes(resp.into_body(), usize::MAX).await.unwrap();
        assert_eq!(&body[..], b"found");
    }

    #[tokio::test]
    async fn proxy_preserves_error_status() {
        let mock = wiremock::MockServer::start().await;
        wiremock::Mock::given(wiremock::matchers::method("POST"))
            .and(wiremock::matchers::path("/oauth/token"))
            .respond_with(
                wiremock::ResponseTemplate::new(400)
                    .set_body_string("bad request")
                    .insert_header("www-authenticate", "DPoP error=\"use_dpop_nonce\""),
            )
            .mount(&mock)
            .await;

        let state = test_state(&mock.uri());
        let app = Router::new()
            .route("/aip/{*path}", post(aip_proxy))
            .with_state(state);

        let req = Request::builder()
            .method("POST")
            .uri("/aip/oauth/token")
            .body(Body::from("grant_type=authorization_code"))
            .unwrap();

        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
        assert!(resp.headers().get("www-authenticate").is_some());
    }
}
