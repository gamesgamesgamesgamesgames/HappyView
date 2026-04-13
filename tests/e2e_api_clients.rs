mod common;

use axum::body::Body;
use axum::http::{Request, StatusCode};
use http_body_util::BodyExt;
use serde_json::{Value, json};
use serial_test::serial;
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
    let default = app.state.oauth.default_client();

    // Should be the same Arc (default client)
    assert!(std::sync::Arc::ptr_eq(&client, default));
}

#[tokio::test]
#[serial]
#[ignore]
async fn oauth_registry_get_or_default_returns_default_for_none() {
    let app = TestApp::new().await;

    let client = app.state.oauth.get_or_default(None);
    let default = app.state.oauth.default_client();

    assert!(std::sync::Arc::ptr_eq(&client, default));
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
