mod common;

use axum::body::Body;
use axum::http::{Request, StatusCode};
use happyview::oauth::pds_write::generate_dpop_proof;
use http_body_util::BodyExt;
use serde_json::json;
use serial_test::serial;
use tower::ServiceExt;

/// Helper to make a POST request with JSON body and extra headers
fn post_json_with_headers(
    uri: &str,
    body: &serde_json::Value,
    headers: Vec<(&str, &str)>,
) -> Request<Body> {
    let mut builder = Request::builder()
        .method("POST")
        .uri(uri)
        .header("content-type", "application/json")
        .header("host", "127.0.0.1");
    for (name, value) in headers {
        builder = builder.header(name, value);
    }
    builder
        .body(Body::from(serde_json::to_vec(body).unwrap()))
        .unwrap()
}

/// Helper to make a DELETE request with headers
fn delete_with_headers(uri: &str, headers: Vec<(&str, &str)>) -> Request<Body> {
    let mut builder = Request::builder()
        .method("DELETE")
        .uri(uri)
        .header("host", "127.0.0.1");
    for (name, value) in headers {
        builder = builder.header(name, value);
    }
    builder.body(Body::empty()).unwrap()
}

async fn response_json(resp: axum::http::Response<Body>) -> serde_json::Value {
    let body = resp.into_body().collect().await.unwrap().to_bytes();
    serde_json::from_slice(&body).unwrap_or(json!(null))
}

#[tokio::test]
#[serial]
async fn test_provision_dpop_key_confidential_client() {
    let app = common::app::TestApp::new_with_encryption().await;
    let (client_key, client_secret, _id) = app.create_api_client("confidential", None).await;

    let req = post_json_with_headers(
        "/oauth/dpop-keys",
        &json!({}),
        vec![
            ("x-client-key", &client_key),
            ("x-client-secret", &client_secret),
        ],
    );

    let resp = app.router.clone().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::CREATED);

    let body = response_json(resp).await;
    assert!(body["provision_id"].is_string());
    assert!(body["dpop_key"]["d"].is_string());
    assert_eq!(body["dpop_key"]["kty"], "EC");
    assert_eq!(body["dpop_key"]["crv"], "P-256");
}

#[tokio::test]
#[serial]
async fn test_provision_dpop_key_public_client_requires_pkce() {
    let app = common::app::TestApp::new_with_encryption().await;
    let (client_key, _secret, _id) = app
        .create_api_client("public", Some(vec!["http://localhost:3000".to_string()]))
        .await;

    // Without PKCE challenge should fail
    let req = post_json_with_headers(
        "/oauth/dpop-keys",
        &json!({}),
        vec![
            ("x-client-key", &client_key),
            ("origin", "http://localhost:3000"),
        ],
    );

    let resp = app.router.clone().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
}

#[tokio::test]
#[serial]
async fn test_provision_dpop_key_public_client_with_pkce() {
    let app = common::app::TestApp::new_with_encryption().await;
    let (client_key, _secret, _id) = app
        .create_api_client("public", Some(vec!["http://localhost:3000".to_string()]))
        .await;

    use base64::Engine;
    use base64::engine::general_purpose::URL_SAFE_NO_PAD;
    use sha2::{Digest, Sha256};

    let verifier = "test-verifier-string-for-pkce-challenge-1234";
    let challenge = URL_SAFE_NO_PAD.encode(Sha256::digest(verifier.as_bytes()));

    let req = post_json_with_headers(
        "/oauth/dpop-keys",
        &json!({
            "pkce_challenge": challenge,
        }),
        vec![
            ("x-client-key", &client_key),
            ("origin", "http://localhost:3000"),
        ],
    );

    let resp = app.router.clone().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::CREATED);

    let body = response_json(resp).await;
    assert!(body["provision_id"].is_string());
}

#[tokio::test]
#[serial]
async fn test_register_session_validates_scopes() {
    let app = common::app::TestApp::new_with_encryption().await;
    let (client_key, client_secret, _id) = app.create_api_client("confidential", None).await;

    // Provision a key first
    let key_req = post_json_with_headers(
        "/oauth/dpop-keys",
        &json!({}),
        vec![
            ("x-client-key", &client_key),
            ("x-client-secret", &client_secret),
        ],
    );
    let key_resp = app.router.clone().oneshot(key_req).await.unwrap();
    let key_body = response_json(key_resp).await;
    let provision_id = key_body["provision_id"].as_str().unwrap();

    // Try to register with a scope the client doesn't have
    let req = post_json_with_headers(
        "/oauth/sessions",
        &json!({
            "provision_id": provision_id,
            "did": "did:plc:test123",
            "access_token": "test-token",
            "scopes": "atproto com.unauthorized.scope",
        }),
        vec![
            ("x-client-key", &client_key),
            ("x-client-secret", &client_secret),
        ],
    );

    let resp = app.router.clone().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
}

#[tokio::test]
#[serial]
async fn test_register_session_requires_atproto_scope() {
    let app = common::app::TestApp::new_with_encryption().await;
    let (client_key, client_secret, _id) = app.create_api_client("confidential", None).await;

    let key_req = post_json_with_headers(
        "/oauth/dpop-keys",
        &json!({}),
        vec![
            ("x-client-key", &client_key),
            ("x-client-secret", &client_secret),
        ],
    );
    let key_resp = app.router.clone().oneshot(key_req).await.unwrap();
    let key_body = response_json(key_resp).await;
    let provision_id = key_body["provision_id"].as_str().unwrap();

    let req = post_json_with_headers(
        "/oauth/sessions",
        &json!({
            "provision_id": provision_id,
            "did": "did:plc:test123",
            "access_token": "test-token",
            "scopes": "transition:generic",
        }),
        vec![
            ("x-client-key", &client_key),
            ("x-client-secret", &client_secret),
        ],
    );

    let resp = app.router.clone().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
}

#[tokio::test]
#[serial]
async fn test_full_flow_provision_register_delete() {
    let app = common::app::TestApp::new_with_encryption().await;
    let (client_key, client_secret, _id) = app.create_api_client("confidential", None).await;

    // 1. Provision key
    let key_req = post_json_with_headers(
        "/oauth/dpop-keys",
        &json!({}),
        vec![
            ("x-client-key", &client_key),
            ("x-client-secret", &client_secret),
        ],
    );
    let key_resp = app.router.clone().oneshot(key_req).await.unwrap();
    assert_eq!(key_resp.status(), StatusCode::CREATED);
    let key_body = response_json(key_resp).await;
    let provision_id = key_body["provision_id"].as_str().unwrap();

    // 2. Register session
    let session_req = post_json_with_headers(
        "/oauth/sessions",
        &json!({
            "provision_id": provision_id,
            "did": "did:plc:testuser",
            "access_token": "test-access-token-123",
            "refresh_token": "test-refresh-token-456",
            "scopes": "atproto",
            "pds_url": "https://pds.example.com",
        }),
        vec![
            ("x-client-key", &client_key),
            ("x-client-secret", &client_secret),
        ],
    );
    let session_resp = app.router.clone().oneshot(session_req).await.unwrap();
    assert_eq!(session_resp.status(), StatusCode::CREATED);
    let session_body = response_json(session_resp).await;
    assert_eq!(session_body["did"], "did:plc:testuser");

    // 3. Delete session
    let delete_req = delete_with_headers(
        "/oauth/sessions/did:plc:testuser",
        vec![
            ("x-client-key", &client_key),
            ("x-client-secret", &client_secret),
        ],
    );
    let delete_resp = app.router.clone().oneshot(delete_req).await.unwrap();
    assert_eq!(delete_resp.status(), StatusCode::NO_CONTENT);

    // 4. Verify session is gone (try to delete again)
    let delete_req2 = delete_with_headers(
        "/oauth/sessions/did:plc:testuser",
        vec![
            ("x-client-key", &client_key),
            ("x-client-secret", &client_secret),
        ],
    );
    let delete_resp2 = app.router.clone().oneshot(delete_req2).await.unwrap();
    assert_eq!(delete_resp2.status(), StatusCode::NOT_FOUND);
}

#[tokio::test]
#[serial]
async fn test_xrpc_rejects_bearer_auth() {
    let app = common::app::TestApp::new_with_encryption().await;

    // Bearer auth should be explicitly rejected on XRPC routes
    let req = Request::builder()
        .method("GET")
        .uri("/xrpc/com.example.test.getStuff")
        .header("host", "127.0.0.1")
        .header("x-client-key", "hvc_fake")
        .header("authorization", "Bearer hv_some-api-key")
        .body(Body::empty())
        .unwrap();

    let resp = app.router.clone().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    let body = response_json(resp).await;
    let msg = body["error"].as_str().unwrap_or_default();
    assert!(
        msg.contains("XRPC routes do not accept Bearer auth"),
        "expected Bearer rejection message, got: {msg}"
    );
}

#[tokio::test]
#[serial]
async fn test_xrpc_allows_anonymous_queries() {
    let app = common::app::TestApp::new_with_encryption().await;

    // Anonymous access (no auth header) should pass through to lexicon lookup.
    // Since no lexicon is registered, we expect a proxy attempt or 502, not 401.
    let req = Request::builder()
        .method("GET")
        .uri("/xrpc/com.example.test.getStuff")
        .header("host", "127.0.0.1")
        .header("x-client-key", "hvc_fake")
        .body(Body::empty())
        .unwrap();

    let resp = app.router.clone().oneshot(req).await.unwrap();
    // Not a 401 — anonymous access was allowed, the error is from the handler (no lexicon)
    assert_ne!(
        resp.status(),
        StatusCode::UNAUTHORIZED,
        "anonymous XRPC queries should not require auth"
    );
}

#[tokio::test]
#[serial]
async fn test_xrpc_procedure_requires_dpop_auth() {
    let app = common::app::TestApp::new_with_encryption().await;

    // POST to an XRPC procedure without DPoP auth should be rejected
    let req = Request::builder()
        .method("POST")
        .uri("/xrpc/com.example.test.createStuff")
        .header("host", "127.0.0.1")
        .header("x-client-key", "hvc_fake")
        .header("content-type", "application/json")
        .body(Body::from("{}"))
        .unwrap();

    let resp = app.router.clone().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    let body = response_json(resp).await;
    let msg = body["error"].as_str().unwrap_or_default();
    assert!(
        msg.contains("DPoP authentication"),
        "expected DPoP requirement message, got: {msg}"
    );
}

#[tokio::test]
#[serial]
async fn test_xrpc_dpop_auth_accepted() {
    let app = common::app::TestApp::new_with_encryption().await;
    let (client_key, client_secret, _id) = app.create_api_client("confidential", None).await;

    // 1. Provision key
    let key_req = post_json_with_headers(
        "/oauth/dpop-keys",
        &json!({}),
        vec![
            ("x-client-key", &client_key),
            ("x-client-secret", &client_secret),
        ],
    );
    let key_resp = app.router.clone().oneshot(key_req).await.unwrap();
    assert_eq!(key_resp.status(), StatusCode::CREATED);
    let key_body = response_json(key_resp).await;
    let provision_id = key_body["provision_id"].as_str().unwrap();
    let dpop_key = &key_body["dpop_key"];

    // 2. Register session
    let access_token = "test-xrpc-access-token";
    let session_req = post_json_with_headers(
        "/oauth/sessions",
        &json!({
            "provision_id": provision_id,
            "did": "did:plc:xrpcuser",
            "access_token": access_token,
            "scopes": "atproto",
            "pds_url": "https://pds.example.com",
        }),
        vec![
            ("x-client-key", &client_key),
            ("x-client-secret", &client_secret),
        ],
    );
    let session_resp = app.router.clone().oneshot(session_req).await.unwrap();
    assert_eq!(session_resp.status(), StatusCode::CREATED);

    // 3. Generate a DPoP proof for an XRPC GET request
    let request_url = "http://127.0.0.1:0/xrpc/com.example.test.getStuff";
    let proof = generate_dpop_proof(dpop_key, "GET", request_url, access_token)
        .expect("failed to generate DPoP proof");

    // 4. Make an XRPC request with DPoP auth
    let xrpc_req = Request::builder()
        .method("GET")
        .uri("/xrpc/com.example.test.getStuff")
        .header("host", "127.0.0.1:0")
        .header("x-client-key", &client_key)
        .header("authorization", format!("DPoP {}", access_token))
        .header("dpop", &proof)
        .body(Body::empty())
        .unwrap();

    let xrpc_resp = app.router.clone().oneshot(xrpc_req).await.unwrap();
    // Auth should succeed — any non-401 status means DPoP auth was accepted.
    // We expect a 502 (proxy attempt for unknown lexicon) or similar, not 401.
    assert_ne!(
        xrpc_resp.status(),
        StatusCode::UNAUTHORIZED,
        "DPoP-authenticated XRPC request should not get 401"
    );
}
