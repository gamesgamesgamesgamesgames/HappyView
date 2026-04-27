mod common;

use axum::body::Body;
use axum::http::{Request, StatusCode};
use happyview::db::{adapt_sql, now_rfc3339};
use happyview::oauth::pds_write::generate_dpop_proof;
use http_body_util::BodyExt;
use serde_json::{Value, json};
use serial_test::serial;
use sha2::Digest;
use tower::ServiceExt;

use common::app::TestApp;

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

async fn json_body(resp: axum::response::Response) -> Value {
    let body = resp.into_body().collect().await.unwrap().to_bytes();
    serde_json::from_slice(&body).unwrap()
}

fn admin_get(
    uri: &str,
    cookie: (axum::http::HeaderName, axum::http::HeaderValue),
) -> Request<Body> {
    Request::builder()
        .uri(uri)
        .header(cookie.0, cookie.1)
        .body(Body::empty())
        .unwrap()
}

fn admin_post(
    uri: &str,
    cookie: (axum::http::HeaderName, axum::http::HeaderValue),
    body: &Value,
) -> Request<Body> {
    Request::builder()
        .method("POST")
        .uri(uri)
        .header(cookie.0, cookie.1)
        .header("content-type", "application/json")
        .body(Body::from(serde_json::to_vec(body).unwrap()))
        .unwrap()
}

fn admin_put(
    uri: &str,
    cookie: (axum::http::HeaderName, axum::http::HeaderValue),
    body: &Value,
) -> Request<Body> {
    Request::builder()
        .method("PUT")
        .uri(uri)
        .header(cookie.0, cookie.1)
        .header("content-type", "application/json")
        .body(Body::from(serde_json::to_vec(body).unwrap()))
        .unwrap()
}

fn admin_delete(
    uri: &str,
    cookie: (axum::http::HeaderName, axum::http::HeaderValue),
) -> Request<Body> {
    Request::builder()
        .method("DELETE")
        .uri(uri)
        .header(cookie.0, cookie.1)
        .body(Body::empty())
        .unwrap()
}

fn sample_api_client_body() -> Value {
    json!({
        "name": "Test App",
        "client_id_url": "https://testapp.example.com/oauth-client-metadata.json",
        "client_uri": "https://testapp.example.com",
        "redirect_uris": ["https://happyview.example.com/auth/callback"],
        "scopes": "atproto"
    })
}

// ---------------------------------------------------------------------------
// Create
// ---------------------------------------------------------------------------

#[tokio::test]
#[serial]
#[ignore]
async fn create_api_client_returns_201() {
    let app = TestApp::new().await;
    let body = sample_api_client_body();

    let resp = app
        .router
        .clone()
        .oneshot(admin_post("/admin/api-clients", app.admin_cookie(), &body))
        .await
        .unwrap();

    assert_eq!(resp.status(), StatusCode::CREATED);
    let json = json_body(resp).await;
    assert_eq!(json["name"], "Test App");
    assert_eq!(
        json["client_id_url"],
        "https://testapp.example.com/oauth-client-metadata.json"
    );
    let key = json["client_key"].as_str().unwrap();
    assert!(key.starts_with("hvc_"), "client_key should start with hvc_");
    assert_eq!(key.len(), 36); // "hvc_" (4) + 32 hex chars
    assert!(json["id"].as_str().is_some());
}

#[tokio::test]
#[serial]
#[ignore]
async fn create_api_client_duplicate_client_id_url_fails() {
    let app = TestApp::new().await;
    let body = sample_api_client_body();

    // First create succeeds
    let resp = app
        .router
        .clone()
        .oneshot(admin_post("/admin/api-clients", app.admin_cookie(), &body))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::CREATED);

    // Second create with same client_id_url should fail (UNIQUE constraint)
    let resp = app
        .router
        .clone()
        .oneshot(admin_post("/admin/api-clients", app.admin_cookie(), &body))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::INTERNAL_SERVER_ERROR);
}

#[tokio::test]
#[serial]
#[ignore]
async fn create_api_client_registers_in_oauth_registry() {
    let app = TestApp::new().await;
    let body = sample_api_client_body();

    let resp = app
        .router
        .clone()
        .oneshot(admin_post("/admin/api-clients", app.admin_cookie(), &body))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::CREATED);

    // The OAuth registry should now have this client
    let client_id_url = "https://testapp.example.com/oauth-client-metadata.json";
    assert!(
        app.state.oauth.get(client_id_url).is_some(),
        "OAuth registry should contain the newly created client"
    );
}

// ---------------------------------------------------------------------------
// List
// ---------------------------------------------------------------------------

#[tokio::test]
#[serial]
#[ignore]
async fn list_api_clients_empty() {
    let app = TestApp::new().await;

    let resp = app
        .router
        .clone()
        .oneshot(admin_get("/admin/api-clients", app.admin_cookie()))
        .await
        .unwrap();

    assert_eq!(resp.status(), StatusCode::OK);
    let json = json_body(resp).await;
    assert!(json.as_array().unwrap().is_empty());
}

#[tokio::test]
#[serial]
#[ignore]
async fn list_api_clients_returns_created_clients() {
    let app = TestApp::new().await;

    // Create two clients
    let body1 = json!({
        "name": "App One",
        "client_id_url": "https://one.example.com/oauth-client-metadata.json",
        "client_uri": "https://one.example.com",
        "redirect_uris": ["https://happyview.example.com/auth/callback"],
        "scopes": "atproto"
    });
    let body2 = json!({
        "name": "App Two",
        "client_id_url": "https://two.example.com/oauth-client-metadata.json",
        "client_uri": "https://two.example.com",
        "redirect_uris": ["https://happyview.example.com/auth/callback"],
        "scopes": "atproto"
    });

    app.router
        .clone()
        .oneshot(admin_post("/admin/api-clients", app.admin_cookie(), &body1))
        .await
        .unwrap();
    app.router
        .clone()
        .oneshot(admin_post("/admin/api-clients", app.admin_cookie(), &body2))
        .await
        .unwrap();

    let resp = app
        .router
        .clone()
        .oneshot(admin_get("/admin/api-clients", app.admin_cookie()))
        .await
        .unwrap();

    assert_eq!(resp.status(), StatusCode::OK);
    let json = json_body(resp).await;
    let arr = json.as_array().unwrap();
    assert_eq!(arr.len(), 2);

    // Verify fields are present
    for client in arr {
        assert!(client["id"].as_str().is_some());
        assert!(client["client_key"].as_str().is_some());
        assert!(client["name"].as_str().is_some());
        assert!(client["client_id_url"].as_str().is_some());
        assert!(client["is_active"].as_bool().is_some());
        assert!(client["created_by"].as_str().is_some());
    }
}

// ---------------------------------------------------------------------------
// Get
// ---------------------------------------------------------------------------

#[tokio::test]
#[serial]
#[ignore]
async fn get_api_client_returns_details() {
    let app = TestApp::new().await;
    let body = sample_api_client_body();

    let create_resp = app
        .router
        .clone()
        .oneshot(admin_post("/admin/api-clients", app.admin_cookie(), &body))
        .await
        .unwrap();
    let created = json_body(create_resp).await;
    let id = created["id"].as_str().unwrap();

    let resp = app
        .router
        .clone()
        .oneshot(admin_get(
            &format!("/admin/api-clients/{id}"),
            app.admin_cookie(),
        ))
        .await
        .unwrap();

    assert_eq!(resp.status(), StatusCode::OK);
    let json = json_body(resp).await;
    assert_eq!(json["name"], "Test App");
    assert_eq!(
        json["client_id_url"],
        "https://testapp.example.com/oauth-client-metadata.json"
    );
    assert_eq!(json["client_uri"], "https://testapp.example.com");
    assert_eq!(json["scopes"], "atproto");
    assert_eq!(json["is_active"], true);
    assert_eq!(json["created_by"], "did:plc:testadmin");
    assert!(json["redirect_uris"].as_array().unwrap().len() == 1);
}

#[tokio::test]
#[serial]
#[ignore]
async fn get_api_client_not_found() {
    let app = TestApp::new().await;

    let resp = app
        .router
        .clone()
        .oneshot(admin_get(
            "/admin/api-clients/00000000-0000-0000-0000-000000000000",
            app.admin_cookie(),
        ))
        .await
        .unwrap();

    assert_eq!(resp.status(), StatusCode::NOT_FOUND);
}

// ---------------------------------------------------------------------------
// Update
// ---------------------------------------------------------------------------

#[tokio::test]
#[serial]
#[ignore]
async fn update_api_client_changes_fields() {
    let app = TestApp::new().await;

    // Create
    let create_resp = app
        .router
        .clone()
        .oneshot(admin_post(
            "/admin/api-clients",
            app.admin_cookie(),
            &sample_api_client_body(),
        ))
        .await
        .unwrap();
    let created = json_body(create_resp).await;
    let id = created["id"].as_str().unwrap();

    // Update
    let update_body = json!({
        "name": "Updated App",
        "scopes": "atproto transition:generic"
    });
    let resp = app
        .router
        .clone()
        .oneshot(admin_put(
            &format!("/admin/api-clients/{id}"),
            app.admin_cookie(),
            &update_body,
        ))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::NO_CONTENT);

    // Verify
    let resp = app
        .router
        .clone()
        .oneshot(admin_get(
            &format!("/admin/api-clients/{id}"),
            app.admin_cookie(),
        ))
        .await
        .unwrap();
    let json = json_body(resp).await;
    assert_eq!(json["name"], "Updated App");
    assert_eq!(json["scopes"], "atproto transition:generic");
    // Unchanged fields should remain
    assert_eq!(json["client_uri"], "https://testapp.example.com");
}

#[tokio::test]
#[serial]
#[ignore]
async fn update_api_client_not_found() {
    let app = TestApp::new().await;

    let resp = app
        .router
        .clone()
        .oneshot(admin_put(
            "/admin/api-clients/00000000-0000-0000-0000-000000000000",
            app.admin_cookie(),
            &json!({"name": "Nope"}),
        ))
        .await
        .unwrap();

    assert_eq!(resp.status(), StatusCode::NOT_FOUND);
}

#[tokio::test]
#[serial]
#[ignore]
async fn update_api_client_deactivate_removes_from_registry() {
    let app = TestApp::new().await;

    let create_resp = app
        .router
        .clone()
        .oneshot(admin_post(
            "/admin/api-clients",
            app.admin_cookie(),
            &sample_api_client_body(),
        ))
        .await
        .unwrap();
    let created = json_body(create_resp).await;
    let id = created["id"].as_str().unwrap();

    let client_id_url = "https://testapp.example.com/oauth-client-metadata.json";
    assert!(app.state.oauth.get(client_id_url).is_some());

    // Deactivate
    let resp = app
        .router
        .clone()
        .oneshot(admin_put(
            &format!("/admin/api-clients/{id}"),
            app.admin_cookie(),
            &json!({"is_active": false}),
        ))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::NO_CONTENT);

    // Should be removed from registry
    assert!(
        app.state.oauth.get(client_id_url).is_none(),
        "Deactivated client should be removed from OAuth registry"
    );
}

// ---------------------------------------------------------------------------
// Delete
// ---------------------------------------------------------------------------

#[tokio::test]
#[serial]
#[ignore]
async fn delete_api_client_returns_204() {
    let app = TestApp::new().await;

    let create_resp = app
        .router
        .clone()
        .oneshot(admin_post(
            "/admin/api-clients",
            app.admin_cookie(),
            &sample_api_client_body(),
        ))
        .await
        .unwrap();
    let created = json_body(create_resp).await;
    let id = created["id"].as_str().unwrap();

    let resp = app
        .router
        .clone()
        .oneshot(admin_delete(
            &format!("/admin/api-clients/{id}"),
            app.admin_cookie(),
        ))
        .await
        .unwrap();

    assert_eq!(resp.status(), StatusCode::NO_CONTENT);

    // Verify gone from list
    let resp = app
        .router
        .clone()
        .oneshot(admin_get("/admin/api-clients", app.admin_cookie()))
        .await
        .unwrap();
    let json = json_body(resp).await;
    assert!(json.as_array().unwrap().is_empty());
}

#[tokio::test]
#[serial]
#[ignore]
async fn delete_api_client_removes_from_oauth_registry() {
    let app = TestApp::new().await;

    let create_resp = app
        .router
        .clone()
        .oneshot(admin_post(
            "/admin/api-clients",
            app.admin_cookie(),
            &sample_api_client_body(),
        ))
        .await
        .unwrap();
    let created = json_body(create_resp).await;
    let id = created["id"].as_str().unwrap();

    let client_id_url = "https://testapp.example.com/oauth-client-metadata.json";
    assert!(app.state.oauth.get(client_id_url).is_some());

    app.router
        .clone()
        .oneshot(admin_delete(
            &format!("/admin/api-clients/{id}"),
            app.admin_cookie(),
        ))
        .await
        .unwrap();

    assert!(
        app.state.oauth.get(client_id_url).is_none(),
        "Deleted client should be removed from OAuth registry"
    );
}

#[tokio::test]
#[serial]
#[ignore]
async fn delete_api_client_not_found() {
    let app = TestApp::new().await;

    let resp = app
        .router
        .clone()
        .oneshot(admin_delete(
            "/admin/api-clients/00000000-0000-0000-0000-000000000000",
            app.admin_cookie(),
        ))
        .await
        .unwrap();

    assert_eq!(resp.status(), StatusCode::NOT_FOUND);
}

// ---------------------------------------------------------------------------
// Permission enforcement
// ---------------------------------------------------------------------------

#[tokio::test]
#[serial]
#[ignore]
async fn api_clients_no_auth_returns_401() {
    let app = TestApp::new().await;

    let resp = app
        .router
        .clone()
        .oneshot(
            Request::builder()
                .uri("/admin/api-clients")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
#[serial]
#[ignore]
async fn api_clients_non_admin_returns_403() {
    let app = TestApp::new().await;

    let resp = app
        .router
        .clone()
        .oneshot(admin_get(
            "/admin/api-clients",
            common::auth::admin_cookie_header("did:plc:notadmin", &app.state.cookie_key),
        ))
        .await
        .unwrap();

    assert_eq!(resp.status(), StatusCode::FORBIDDEN);
}

// ---------------------------------------------------------------------------
// OAuth registry (unit-level via AppState)
// ---------------------------------------------------------------------------

#[tokio::test]
#[serial]
#[ignore]
async fn oauth_registry_get_or_default_returns_default_for_unknown() {
    let app = TestApp::new().await;

    let client = app
        .state
        .oauth
        .get_or_default(Some("https://unknown.example.com/metadata.json"));
    let default = app.state.oauth.primary_client();

    // Should be the same Arc (default client)
    assert!(std::sync::Arc::ptr_eq(&client, &default));
}

#[tokio::test]
#[serial]
#[ignore]
async fn oauth_registry_get_or_default_returns_default_for_none() {
    let app = TestApp::new().await;

    let client = app.state.oauth.get_or_default(None);
    let default = app.state.oauth.primary_client();

    assert!(std::sync::Arc::ptr_eq(&client, &default));
}

// ---------------------------------------------------------------------------
// Rate limit config on API clients
// ---------------------------------------------------------------------------

#[tokio::test]
#[serial]
#[ignore]
async fn create_api_client_with_rate_limit_overrides() {
    let app = TestApp::new().await;
    let body = json!({
        "name": "Rate Limited App",
        "client_id_url": "https://ratelimited.example.com/oauth-client-metadata.json",
        "client_uri": "https://ratelimited.example.com",
        "redirect_uris": ["https://happyview.example.com/auth/callback"],
        "scopes": "atproto",
        "rate_limit_capacity": 50,
        "rate_limit_refill_rate": 1.5
    });

    let resp = app
        .router
        .clone()
        .oneshot(admin_post("/admin/api-clients", app.admin_cookie(), &body))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::CREATED);
    let created = json_body(resp).await;
    let id = created["id"].as_str().unwrap();

    // Verify overrides persisted
    let resp = app
        .router
        .clone()
        .oneshot(admin_get(
            &format!("/admin/api-clients/{id}"),
            app.admin_cookie(),
        ))
        .await
        .unwrap();
    let json = json_body(resp).await;
    assert_eq!(json["rate_limit_capacity"], 50);
    assert_eq!(json["rate_limit_refill_rate"], 1.5);
}

// ---------------------------------------------------------------------------
// Self-service API client creation (POST /oauth/api-clients)
// ---------------------------------------------------------------------------

/// Helper to make a POST request with JSON body and extra headers.
fn post_json_with_headers(
    uri: &str,
    body: &serde_json::Value,
    headers: Vec<(&str, &str)>,
) -> Request<Body> {
    let mut builder = Request::builder()
        .method("POST")
        .uri(uri)
        .header("content-type", "application/json")
        .header("host", "127.0.0.1:0");
    for (name, value) in headers {
        builder = builder.header(name, value);
    }
    builder
        .body(Body::from(serde_json::to_vec(body).unwrap()))
        .unwrap()
}

/// Parse a response body as JSON, returning `null` on empty/invalid bodies.
async fn response_json(resp: axum::response::Response) -> Value {
    let body = resp.into_body().collect().await.unwrap().to_bytes();
    serde_json::from_slice(&body).unwrap_or(json!(null))
}

/// Runs the full DPoP provisioning flow and returns the values needed to call
/// the self-service endpoint:
/// `(client_key, dpop_key_json, access_token)`
///
/// `user_did` is the DID that will be associated with the DPoP session.
async fn setup_dpop_session(app: &TestApp, user_did: &str) -> (String, Value, String) {
    let (client_key, client_secret, _id) = app.create_api_client("confidential", None).await;

    // 1. Provision DPoP key
    let key_req = post_json_with_headers(
        "/oauth/dpop-keys",
        &json!({}),
        vec![
            ("x-client-key", &client_key),
            ("x-client-secret", &client_secret),
        ],
    );
    let key_resp = app.router.clone().oneshot(key_req).await.unwrap();
    assert_eq!(
        key_resp.status(),
        StatusCode::CREATED,
        "dpop key provisioning failed"
    );
    let key_body = response_json(key_resp).await;
    let provision_id = key_body["provision_id"].as_str().unwrap().to_string();
    let dpop_key = key_body["dpop_key"].clone();

    // 2. Register session
    let access_token = format!("test-access-{}", uuid::Uuid::new_v4());
    let session_req = post_json_with_headers(
        "/oauth/sessions",
        &json!({
            "provision_id": provision_id,
            "did": user_did,
            "access_token": &access_token,
            "scopes": "atproto",
            "pds_url": "https://pds.example.com",
        }),
        vec![
            ("x-client-key", &client_key),
            ("x-client-secret", &client_secret),
        ],
    );
    let session_resp = app.router.clone().oneshot(session_req).await.unwrap();
    assert_eq!(
        session_resp.status(),
        StatusCode::CREATED,
        "session registration failed"
    );

    (client_key, dpop_key, access_token)
}

/// Build a self-service POST /oauth/api-clients request with full DPoP auth.
fn self_service_request(
    client_key: &str,
    access_token: &str,
    dpop_proof: &str,
    body: &Value,
) -> Request<Body> {
    Request::builder()
        .method("POST")
        .uri("/oauth/api-clients")
        .header("host", "127.0.0.1:0")
        .header("content-type", "application/json")
        .header("x-client-key", client_key)
        .header("authorization", format!("DPoP {}", access_token))
        .header("dpop", dpop_proof)
        .body(Body::from(serde_json::to_vec(body).unwrap()))
        .unwrap()
}

// ---------------------------------------------------------------------------
// Happy path
// ---------------------------------------------------------------------------

#[tokio::test]
#[serial]
#[ignore]
async fn test_self_service_create_confidential_child_client() {
    let app = TestApp::new_with_encryption().await;
    let (client_key, dpop_key, access_token) = setup_dpop_session(&app, "did:plc:testadmin").await;

    let request_url = "http://127.0.0.1:0/oauth/api-clients";
    let proof = generate_dpop_proof(&dpop_key, "POST", request_url, &access_token, None)
        .expect("failed to generate DPoP proof");

    let body = json!({
        "name": "My Confidential Child",
        "client_id_url": "https://child-confidential.example.com/oauth-client-metadata.json",
        "client_uri": "https://child-confidential.example.com",
        "redirect_uris": ["https://child-confidential.example.com/callback"],
        "scopes": "atproto",
        "client_type": "confidential"
    });

    let req = self_service_request(&client_key, &access_token, &proof, &body);
    let resp = app.router.clone().oneshot(req).await.unwrap();

    assert_eq!(resp.status(), StatusCode::CREATED);
    let json = response_json(resp).await;

    // Verify all expected fields
    assert!(json["id"].as_str().is_some(), "response should have id");
    let key = json["client_key"].as_str().unwrap();
    assert!(key.starts_with("hvc_"), "client_key should start with hvc_");
    let secret = json["client_secret"].as_str().unwrap();
    assert!(
        secret.starts_with("hvs_"),
        "client_secret should start with hvs_"
    );
    assert_eq!(json["name"], "My Confidential Child");
    assert_eq!(
        json["client_id_url"],
        "https://child-confidential.example.com/oauth-client-metadata.json"
    );
    assert_eq!(json["client_type"], "confidential");
}

#[tokio::test]
#[serial]
#[ignore]
async fn test_self_service_create_public_child_client() {
    let app = TestApp::new_with_encryption().await;
    let (client_key, dpop_key, access_token) = setup_dpop_session(&app, "did:plc:testadmin").await;

    let request_url = "http://127.0.0.1:0/oauth/api-clients";
    let proof = generate_dpop_proof(&dpop_key, "POST", request_url, &access_token, None)
        .expect("failed to generate DPoP proof");

    let body = json!({
        "name": "My Public Child",
        "client_id_url": "https://child-public.example.com/oauth-client-metadata.json",
        "client_uri": "https://child-public.example.com",
        "redirect_uris": ["https://child-public.example.com/callback"],
        "scopes": "atproto",
        "client_type": "public"
    });

    let req = self_service_request(&client_key, &access_token, &proof, &body);
    let resp = app.router.clone().oneshot(req).await.unwrap();

    assert_eq!(resp.status(), StatusCode::CREATED);
    let json = response_json(resp).await;

    assert!(json["id"].as_str().is_some(), "response should have id");
    let key = json["client_key"].as_str().unwrap();
    assert!(key.starts_with("hvc_"), "client_key should start with hvc_");
    assert_eq!(json["name"], "My Public Child");
    assert_eq!(
        json["client_id_url"],
        "https://child-public.example.com/oauth-client-metadata.json"
    );
    assert_eq!(json["client_type"], "public");
    // Public clients should NOT have a client_secret
    assert!(
        json["client_secret"].is_null(),
        "public client should not have a client_secret"
    );
}

// ---------------------------------------------------------------------------
// Error cases
// ---------------------------------------------------------------------------

#[tokio::test]
#[serial]
#[ignore]
async fn test_self_service_child_cannot_create_children() {
    let app = TestApp::new_with_encryption().await;

    // Create a parent client via the helper (top-level, no parent_client_id).
    let (_parent_key, _parent_secret, parent_id) =
        app.create_api_client("confidential", None).await;

    // Insert a child client directly in the DB with parent_client_id set.
    let child_key = format!("hvc_{}", hex::encode([0xAAu8; 16]));
    let child_secret = format!("hvs_{}", hex::encode([0xBBu8; 32]));
    let child_secret_hash = hex::encode(sha2::Sha256::digest(child_secret.as_bytes()));
    let child_id = uuid::Uuid::new_v4().to_string();
    let now = now_rfc3339();

    let sql = adapt_sql(
        "INSERT INTO api_clients (id, client_key, client_secret_hash, name, client_id_url, client_uri, redirect_uris, scopes, client_type, is_active, created_by, created_at, updated_at, parent_client_id, owner_did) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, 1, ?, ?, ?, ?, ?)",
        app.state.db_backend,
    );
    sqlx::query(&sql)
        .bind(&child_id)
        .bind(&child_key)
        .bind(&child_secret_hash)
        .bind("child-client")
        .bind("https://child-no-nest.example.com/oauth-client-metadata.json")
        .bind("https://child-no-nest.example.com")
        .bind("[]")
        .bind("atproto")
        .bind("confidential")
        .bind("did:plc:testadmin")
        .bind(&now)
        .bind(&now)
        .bind(&parent_id)
        .bind("did:plc:testadmin")
        .execute(&app.state.db)
        .await
        .expect("failed to insert child client");

    // The endpoint checks parent_client_id IS NULL at step 6, BEFORE DPoP
    // validation. So we just need the DPoP headers to exist — they do not
    // need to be cryptographically valid.
    let body = json!({
        "name": "Grandchild",
        "client_id_url": "https://grandchild.example.com/oauth-client-metadata.json",
        "client_uri": "https://grandchild.example.com",
        "redirect_uris": ["https://grandchild.example.com/callback"],
        "scopes": "atproto",
        "client_type": "confidential"
    });

    let req = Request::builder()
        .method("POST")
        .uri("/oauth/api-clients")
        .header("host", "127.0.0.1:0")
        .header("content-type", "application/json")
        .header("x-client-key", &child_key)
        .header("authorization", "DPoP fake-token")
        .header("dpop", "fake-proof")
        .body(Body::from(serde_json::to_vec(&body).unwrap()))
        .unwrap();

    let resp = app.router.clone().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::FORBIDDEN);
}

#[tokio::test]
#[serial]
#[ignore]
async fn test_self_service_duplicate_client_id_url() {
    let app = TestApp::new_with_encryption().await;
    let (client_key, dpop_key, access_token) = setup_dpop_session(&app, "did:plc:testadmin").await;

    let shared_url = "https://dup-test.example.com/oauth-client-metadata.json";

    // First creation should succeed.
    let request_url = "http://127.0.0.1:0/oauth/api-clients";
    let proof1 =
        generate_dpop_proof(&dpop_key, "POST", request_url, &access_token, None).expect("proof 1");

    let body = json!({
        "name": "First Child",
        "client_id_url": shared_url,
        "client_uri": "https://dup-test.example.com",
        "redirect_uris": ["https://dup-test.example.com/callback"],
        "scopes": "atproto",
        "client_type": "confidential"
    });

    let req1 = self_service_request(&client_key, &access_token, &proof1, &body);
    let resp1 = app.router.clone().oneshot(req1).await.unwrap();
    assert_eq!(resp1.status(), StatusCode::CREATED);

    // Second creation with the same client_id_url should fail with 409.
    let proof2 =
        generate_dpop_proof(&dpop_key, "POST", request_url, &access_token, None).expect("proof 2");

    let body2 = json!({
        "name": "Second Child",
        "client_id_url": shared_url,
        "client_uri": "https://dup-test2.example.com",
        "redirect_uris": ["https://dup-test2.example.com/callback"],
        "scopes": "atproto",
        "client_type": "confidential"
    });

    let req2 = self_service_request(&client_key, &access_token, &proof2, &body2);
    let resp2 = app.router.clone().oneshot(req2).await.unwrap();
    assert_eq!(resp2.status(), StatusCode::CONFLICT);
}

#[tokio::test]
#[serial]
#[ignore]
async fn test_self_service_missing_client_key() {
    let app = TestApp::new_with_encryption().await;

    let body = json!({
        "name": "No Key Client",
        "client_id_url": "https://nokey.example.com/oauth-client-metadata.json",
        "client_uri": "https://nokey.example.com",
        "redirect_uris": ["https://nokey.example.com/callback"],
        "scopes": "atproto",
        "client_type": "confidential"
    });

    // No x-client-key header at all.
    let req = Request::builder()
        .method("POST")
        .uri("/oauth/api-clients")
        .header("host", "127.0.0.1:0")
        .header("content-type", "application/json")
        .header("authorization", "DPoP fake-token")
        .header("dpop", "fake-proof")
        .body(Body::from(serde_json::to_vec(&body).unwrap()))
        .unwrap();

    let resp = app.router.clone().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
#[serial]
#[ignore]
async fn test_self_service_invalid_client_type() {
    let app = TestApp::new_with_encryption().await;

    // Step 3 (client_type validation) happens before step 5 (client resolution).
    // The request just needs the required headers to exist.
    let body = json!({
        "name": "Invalid Type Client",
        "client_id_url": "https://badtype.example.com/oauth-client-metadata.json",
        "client_uri": "https://badtype.example.com",
        "redirect_uris": ["https://badtype.example.com/callback"],
        "scopes": "atproto",
        "client_type": "invalid"
    });

    let req = Request::builder()
        .method("POST")
        .uri("/oauth/api-clients")
        .header("host", "127.0.0.1:0")
        .header("content-type", "application/json")
        .header("x-client-key", "hvc_doesnotmatter")
        .header("authorization", "DPoP fake-token")
        .header("dpop", "fake-proof")
        .body(Body::from(serde_json::to_vec(&body).unwrap()))
        .unwrap();

    let resp = app.router.clone().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
}

#[tokio::test]
#[serial]
#[ignore]
async fn test_self_service_parent_owner_not_in_users() {
    let app = TestApp::new_with_encryption().await;

    // Create a parent API client whose created_by DID is NOT in the users table.
    let orphan_did = "did:plc:orphan";
    let (client_key, client_secret, _id) = {
        use happyview::db::{adapt_sql, now_rfc3339};
        use rand::RngCore;
        use sha2::{Digest, Sha256};

        let mut key_bytes = [0u8; 16];
        rand::rng().fill_bytes(&mut key_bytes);
        let client_key = format!("hvc_{}", hex::encode(key_bytes));

        let mut secret_bytes = [0u8; 32];
        rand::rng().fill_bytes(&mut secret_bytes);
        let client_secret = format!("hvs_{}", hex::encode(secret_bytes));
        let secret_hash = hex::encode(Sha256::digest(client_secret.as_bytes()));

        let id = uuid::Uuid::new_v4().to_string();
        let now = now_rfc3339();

        let sql = adapt_sql(
            "INSERT INTO api_clients (id, client_key, client_secret_hash, name, client_id_url, client_uri, redirect_uris, scopes, client_type, allowed_origins, is_active, created_by, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 1, ?, ?, ?)",
            app.state.db_backend,
        );

        sqlx::query(&sql)
            .bind(&id)
            .bind(&client_key)
            .bind(&secret_hash)
            .bind("orphan-client")
            .bind(format!("https://orphan.example.com/oauth/{}", &id[..8]))
            .bind("https://orphan.example.com")
            .bind("[]")
            .bind("atproto")
            .bind("confidential")
            .bind(None::<String>)
            .bind(orphan_did)
            .bind(&now)
            .bind(&now)
            .execute(&app.state.db)
            .await
            .expect("failed to create orphan API client");

        app.state.rate_limiter.register_client_identity(
            client_key.clone(),
            happyview::rate_limit::ClientIdentity {
                secret_hash,
                client_uri: "https://orphan.example.com".to_string(),
            },
        );

        (client_key, client_secret, id)
    };

    // Provision a DPoP key and session using this orphan parent client.
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
    let provision_id = key_body["provision_id"].as_str().unwrap().to_string();
    let dpop_key = key_body["dpop_key"].clone();

    let access_token = format!("test-access-{}", uuid::Uuid::new_v4());
    let session_req = post_json_with_headers(
        "/oauth/sessions",
        &json!({
            "provision_id": provision_id,
            "did": "did:plc:sessionuser",
            "access_token": &access_token,
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

    let request_url = "http://127.0.0.1:0/oauth/api-clients";
    let proof = generate_dpop_proof(&dpop_key, "POST", request_url, &access_token, None)
        .expect("failed to generate DPoP proof");

    let body = json!({
        "name": "Orphan Owner Child",
        "client_id_url": "https://orphan-child.example.com/oauth-client-metadata.json",
        "client_uri": "https://orphan-child.example.com",
        "redirect_uris": ["https://orphan-child.example.com/callback"],
        "scopes": "atproto",
        "client_type": "confidential"
    });

    let req = self_service_request(&client_key, &access_token, &proof, &body);
    let resp = app.router.clone().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::FORBIDDEN);
}

// ---------------------------------------------------------------------------
// Cascade: deactivate / delete parent cascades to children
// ---------------------------------------------------------------------------

#[tokio::test]
#[serial]
#[ignore]
async fn test_deactivate_parent_cascades_to_children() {
    let app = TestApp::new().await;

    // Create parent via admin API
    let parent_body = json!({
        "name": "Cascade Parent",
        "client_id_url": "https://cascade-deactivate-parent.example.com/oauth-client-metadata.json",
        "client_uri": "https://cascade-deactivate-parent.example.com",
        "redirect_uris": ["https://happyview.example.com/auth/callback"],
        "scopes": "atproto"
    });
    let create_resp = app
        .router
        .clone()
        .oneshot(admin_post(
            "/admin/api-clients",
            app.admin_cookie(),
            &parent_body,
        ))
        .await
        .unwrap();
    assert_eq!(create_resp.status(), StatusCode::CREATED);
    let created = json_body(create_resp).await;
    let parent_id = created["id"].as_str().unwrap().to_string();

    // Insert child directly in DB
    let child_id = uuid::Uuid::new_v4().to_string();
    let child_key = format!("hvc_{}", hex::encode([0xCCu8; 16]));
    let child_hash = hex::encode(sha2::Sha256::digest("hvs_fake_cc".as_bytes()));
    let now = now_rfc3339();

    let sql = adapt_sql(
        "INSERT INTO api_clients (id, client_key, client_secret_hash, name, client_id_url, client_uri, redirect_uris, scopes, client_type, is_active, created_by, created_at, updated_at, parent_client_id, owner_did) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, 1, ?, ?, ?, ?, ?)",
        app.state.db_backend,
    );
    sqlx::query(&sql)
        .bind(&child_id)
        .bind(&child_key)
        .bind(&child_hash)
        .bind("Cascade Child")
        .bind("https://cascade-deactivate-child.example.com/metadata.json")
        .bind("https://cascade-deactivate-child.example.com")
        .bind("[]")
        .bind("atproto")
        .bind("confidential")
        .bind("did:plc:testadmin")
        .bind(&now)
        .bind(&now)
        .bind(&parent_id)
        .bind("did:plc:testadmin")
        .execute(&app.state.db)
        .await
        .expect("failed to insert child");

    // Deactivate the parent
    let deactivate_resp = app
        .router
        .clone()
        .oneshot(admin_put(
            &format!("/admin/api-clients/{parent_id}"),
            app.admin_cookie(),
            &json!({"is_active": false}),
        ))
        .await
        .unwrap();
    assert_eq!(deactivate_resp.status(), StatusCode::NO_CONTENT);

    // Verify parent is deactivated
    let parent_get = app
        .router
        .clone()
        .oneshot(admin_get(
            &format!("/admin/api-clients/{parent_id}"),
            app.admin_cookie(),
        ))
        .await
        .unwrap();
    assert_eq!(parent_get.status(), StatusCode::OK);
    let parent_json = json_body(parent_get).await;
    assert_eq!(
        parent_json["is_active"], false,
        "parent should be deactivated"
    );

    // Verify child is also deactivated
    let child_get = app
        .router
        .clone()
        .oneshot(admin_get(
            &format!("/admin/api-clients/{child_id}"),
            app.admin_cookie(),
        ))
        .await
        .unwrap();
    assert_eq!(child_get.status(), StatusCode::OK);
    let child_json = json_body(child_get).await;
    assert_eq!(
        child_json["is_active"], false,
        "child should be deactivated by cascade"
    );
}

#[tokio::test]
#[serial]
#[ignore]
async fn test_delete_parent_cascades_to_children() {
    let app = TestApp::new().await;

    // Create parent via admin API
    let parent_body = json!({
        "name": "Delete Parent",
        "client_id_url": "https://cascade-delete-parent.example.com/oauth-client-metadata.json",
        "client_uri": "https://cascade-delete-parent.example.com",
        "redirect_uris": ["https://happyview.example.com/auth/callback"],
        "scopes": "atproto"
    });
    let create_resp = app
        .router
        .clone()
        .oneshot(admin_post(
            "/admin/api-clients",
            app.admin_cookie(),
            &parent_body,
        ))
        .await
        .unwrap();
    assert_eq!(create_resp.status(), StatusCode::CREATED);
    let created = json_body(create_resp).await;
    let parent_id = created["id"].as_str().unwrap().to_string();

    // Insert child directly in DB
    let child_id = uuid::Uuid::new_v4().to_string();
    let child_key = format!("hvc_{}", hex::encode([0xDDu8; 16]));
    let child_hash = hex::encode(sha2::Sha256::digest("hvs_fake_dd".as_bytes()));
    let now = now_rfc3339();

    let sql = adapt_sql(
        "INSERT INTO api_clients (id, client_key, client_secret_hash, name, client_id_url, client_uri, redirect_uris, scopes, client_type, is_active, created_by, created_at, updated_at, parent_client_id, owner_did) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, 1, ?, ?, ?, ?, ?)",
        app.state.db_backend,
    );
    sqlx::query(&sql)
        .bind(&child_id)
        .bind(&child_key)
        .bind(&child_hash)
        .bind("Delete Child")
        .bind("https://cascade-delete-child.example.com/metadata.json")
        .bind("https://cascade-delete-child.example.com")
        .bind("[]")
        .bind("atproto")
        .bind("confidential")
        .bind("did:plc:testadmin")
        .bind(&now)
        .bind(&now)
        .bind(&parent_id)
        .bind("did:plc:testadmin")
        .execute(&app.state.db)
        .await
        .expect("failed to insert child");

    // Delete the parent
    let delete_resp = app
        .router
        .clone()
        .oneshot(admin_delete(
            &format!("/admin/api-clients/{parent_id}"),
            app.admin_cookie(),
        ))
        .await
        .unwrap();
    assert_eq!(delete_resp.status(), StatusCode::NO_CONTENT);

    // Verify parent is gone
    let parent_get = app
        .router
        .clone()
        .oneshot(admin_get(
            &format!("/admin/api-clients/{parent_id}"),
            app.admin_cookie(),
        ))
        .await
        .unwrap();
    assert_eq!(parent_get.status(), StatusCode::NOT_FOUND);

    // Verify child is also gone (ON DELETE CASCADE)
    let child_get = app
        .router
        .clone()
        .oneshot(admin_get(
            &format!("/admin/api-clients/{child_id}"),
            app.admin_cookie(),
        ))
        .await
        .unwrap();
    assert_eq!(child_get.status(), StatusCode::NOT_FOUND);
}

// ---------------------------------------------------------------------------
// List filtering: parent_id query param and response fields
// ---------------------------------------------------------------------------

#[tokio::test]
#[serial]
#[ignore]
async fn test_list_api_clients_filter_by_parent() {
    let app = TestApp::new().await;

    // Create two parents via admin API
    let parent1_body = json!({
        "name": "Filter Parent 1",
        "client_id_url": "https://filter-parent-1.example.com/oauth-client-metadata.json",
        "client_uri": "https://filter-parent-1.example.com",
        "redirect_uris": ["https://happyview.example.com/auth/callback"],
        "scopes": "atproto"
    });
    let parent2_body = json!({
        "name": "Filter Parent 2",
        "client_id_url": "https://filter-parent-2.example.com/oauth-client-metadata.json",
        "client_uri": "https://filter-parent-2.example.com",
        "redirect_uris": ["https://happyview.example.com/auth/callback"],
        "scopes": "atproto"
    });

    let p1_resp = app
        .router
        .clone()
        .oneshot(admin_post(
            "/admin/api-clients",
            app.admin_cookie(),
            &parent1_body,
        ))
        .await
        .unwrap();
    assert_eq!(p1_resp.status(), StatusCode::CREATED);
    let p1 = json_body(p1_resp).await;
    let parent1_id = p1["id"].as_str().unwrap().to_string();

    let p2_resp = app
        .router
        .clone()
        .oneshot(admin_post(
            "/admin/api-clients",
            app.admin_cookie(),
            &parent2_body,
        ))
        .await
        .unwrap();
    assert_eq!(p2_resp.status(), StatusCode::CREATED);
    let p2 = json_body(p2_resp).await;
    let parent2_id = p2["id"].as_str().unwrap().to_string();

    // Insert a child under parent 1
    let child1_id = uuid::Uuid::new_v4().to_string();
    let child1_key = format!("hvc_{}", hex::encode([0xE1u8; 16]));
    let child1_hash = hex::encode(sha2::Sha256::digest("hvs_fake_e1".as_bytes()));
    let now = now_rfc3339();

    let sql = adapt_sql(
        "INSERT INTO api_clients (id, client_key, client_secret_hash, name, client_id_url, client_uri, redirect_uris, scopes, client_type, is_active, created_by, created_at, updated_at, parent_client_id, owner_did) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, 1, ?, ?, ?, ?, ?)",
        app.state.db_backend,
    );
    sqlx::query(&sql)
        .bind(&child1_id)
        .bind(&child1_key)
        .bind(&child1_hash)
        .bind("Child of Parent 1")
        .bind("https://filter-child-1.example.com/metadata.json")
        .bind("https://filter-child-1.example.com")
        .bind("[]")
        .bind("atproto")
        .bind("confidential")
        .bind("did:plc:testadmin")
        .bind(&now)
        .bind(&now)
        .bind(&parent1_id)
        .bind("did:plc:testadmin")
        .execute(&app.state.db)
        .await
        .expect("failed to insert child1");

    // Insert a child under parent 2
    let child2_id = uuid::Uuid::new_v4().to_string();
    let child2_key = format!("hvc_{}", hex::encode([0xE2u8; 16]));
    let child2_hash = hex::encode(sha2::Sha256::digest("hvs_fake_e2".as_bytes()));

    let sql2 = adapt_sql(
        "INSERT INTO api_clients (id, client_key, client_secret_hash, name, client_id_url, client_uri, redirect_uris, scopes, client_type, is_active, created_by, created_at, updated_at, parent_client_id, owner_did) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, 1, ?, ?, ?, ?, ?)",
        app.state.db_backend,
    );
    sqlx::query(&sql2)
        .bind(&child2_id)
        .bind(&child2_key)
        .bind(&child2_hash)
        .bind("Child of Parent 2")
        .bind("https://filter-child-2.example.com/metadata.json")
        .bind("https://filter-child-2.example.com")
        .bind("[]")
        .bind("atproto")
        .bind("confidential")
        .bind("did:plc:testadmin")
        .bind(&now)
        .bind(&now)
        .bind(&parent2_id)
        .bind("did:plc:testadmin")
        .execute(&app.state.db)
        .await
        .expect("failed to insert child2");

    // Filter by parent1_id — should return only child1
    let resp = app
        .router
        .clone()
        .oneshot(admin_get(
            &format!("/admin/api-clients?parent_id={parent1_id}"),
            app.admin_cookie(),
        ))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let arr = json_body(resp).await;
    let items = arr.as_array().expect("response should be an array");
    assert_eq!(
        items.len(),
        1,
        "should return exactly one child for parent 1"
    );
    assert_eq!(items[0]["id"], child1_id);
    assert_eq!(items[0]["name"], "Child of Parent 1");

    // Filter by parent2_id — should return only child2
    let resp2 = app
        .router
        .clone()
        .oneshot(admin_get(
            &format!("/admin/api-clients?parent_id={parent2_id}"),
            app.admin_cookie(),
        ))
        .await
        .unwrap();
    assert_eq!(resp2.status(), StatusCode::OK);
    let arr2 = json_body(resp2).await;
    let items2 = arr2.as_array().expect("response should be an array");
    assert_eq!(
        items2.len(),
        1,
        "should return exactly one child for parent 2"
    );
    assert_eq!(items2[0]["id"], child2_id);
    assert_eq!(items2[0]["name"], "Child of Parent 2");
}

#[tokio::test]
#[serial]
#[ignore]
async fn test_list_api_clients_includes_parent_and_owner_fields() {
    let app = TestApp::new().await;

    // Create a top-level parent via admin API
    let parent_body = json!({
        "name": "Fields Parent",
        "client_id_url": "https://fields-parent.example.com/oauth-client-metadata.json",
        "client_uri": "https://fields-parent.example.com",
        "redirect_uris": ["https://happyview.example.com/auth/callback"],
        "scopes": "atproto"
    });
    let create_resp = app
        .router
        .clone()
        .oneshot(admin_post(
            "/admin/api-clients",
            app.admin_cookie(),
            &parent_body,
        ))
        .await
        .unwrap();
    assert_eq!(create_resp.status(), StatusCode::CREATED);
    let created = json_body(create_resp).await;
    let parent_id = created["id"].as_str().unwrap().to_string();

    // Insert a child with owner_did set
    let child_id = uuid::Uuid::new_v4().to_string();
    let child_key = format!("hvc_{}", hex::encode([0xFFu8; 16]));
    let child_hash = hex::encode(sha2::Sha256::digest("hvs_fake_ff".as_bytes()));
    let now = now_rfc3339();
    let owner_did = "did:plc:childowner";

    let sql = adapt_sql(
        "INSERT INTO api_clients (id, client_key, client_secret_hash, name, client_id_url, client_uri, redirect_uris, scopes, client_type, is_active, created_by, created_at, updated_at, parent_client_id, owner_did) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, 1, ?, ?, ?, ?, ?)",
        app.state.db_backend,
    );
    sqlx::query(&sql)
        .bind(&child_id)
        .bind(&child_key)
        .bind(&child_hash)
        .bind("Fields Child")
        .bind("https://fields-child.example.com/metadata.json")
        .bind("https://fields-child.example.com")
        .bind("[]")
        .bind("atproto")
        .bind("confidential")
        .bind("did:plc:testadmin")
        .bind(&now)
        .bind(&now)
        .bind(&parent_id)
        .bind(owner_did)
        .execute(&app.state.db)
        .await
        .expect("failed to insert child");

    // List all clients
    let resp = app
        .router
        .clone()
        .oneshot(admin_get("/admin/api-clients", app.admin_cookie()))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let arr = json_body(resp).await;
    let items = arr.as_array().expect("response should be an array");
    assert_eq!(items.len(), 2, "should have parent + child");

    // Find the parent in the list
    let parent_item = items
        .iter()
        .find(|c| c["id"].as_str() == Some(&parent_id))
        .expect("parent should be in list");
    // Top-level client has null parent_client_id and null owner_did
    assert!(
        parent_item["parent_client_id"].is_null(),
        "top-level client should have null parent_client_id"
    );
    assert!(
        parent_item["owner_did"].is_null(),
        "admin-created client should have null owner_did"
    );

    // Find the child in the list
    let child_item = items
        .iter()
        .find(|c| c["id"].as_str() == Some(&child_id))
        .expect("child should be in list");
    assert_eq!(
        child_item["parent_client_id"].as_str(),
        Some(parent_id.as_str()),
        "child should reference its parent"
    );
    assert_eq!(
        child_item["owner_did"].as_str(),
        Some(owner_did),
        "child should have owner_did set"
    );
}
