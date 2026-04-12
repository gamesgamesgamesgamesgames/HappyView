mod common;

use axum::body::Body;
use axum::http::{Method, Request, StatusCode};
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

fn admin_put(
    uri: &str,
    cookie: (axum::http::HeaderName, axum::http::HeaderValue),
    body: &Value,
) -> Request<Body> {
    Request::builder()
        .method(Method::PUT)
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
        .method(Method::DELETE)
        .uri(uri)
        .header(cookie.0, cookie.1)
        .body(Body::empty())
        .unwrap()
}

// ---------------------------------------------------------------------------
// Settings tests
// ---------------------------------------------------------------------------

#[tokio::test]
#[serial]
#[ignore]
async fn settings_crud() {
    let app = TestApp::new().await;

    // PUT a setting
    let resp = app
        .router
        .clone()
        .oneshot(admin_put(
            "/admin/settings/app_name",
            app.admin_cookie(),
            &json!({ "value": "Test App" }),
        ))
        .await
        .unwrap();

    assert!(
        resp.status().is_success(),
        "expected success on PUT, got {}",
        resp.status()
    );

    // GET all settings and verify the entry appears with source: "database"
    let resp = app
        .router
        .clone()
        .oneshot(admin_get("/admin/settings", app.admin_cookie()))
        .await
        .unwrap();

    assert_eq!(resp.status(), StatusCode::OK);
    let json = json_body(resp).await;
    let settings = json.as_array().unwrap();
    let app_name_entry = settings
        .iter()
        .find(|s| s["key"] == "app_name")
        .expect("app_name entry not found in settings");
    assert_eq!(app_name_entry["source"], "database");

    // DELETE the setting
    let resp = app
        .router
        .clone()
        .oneshot(admin_delete("/admin/settings/app_name", app.admin_cookie()))
        .await
        .unwrap();

    assert!(
        resp.status().is_success(),
        "expected success on DELETE, got {}",
        resp.status()
    );

    // GET again and verify it's removed
    let resp = app
        .router
        .clone()
        .oneshot(admin_get("/admin/settings", app.admin_cookie()))
        .await
        .unwrap();

    assert_eq!(resp.status(), StatusCode::OK);
    let json = json_body(resp).await;
    let settings = json.as_array().unwrap();
    let app_name_entry = settings.iter().find(|s| s["key"] == "app_name");
    assert!(
        app_name_entry.is_none(),
        "app_name entry should have been deleted"
    );
}

#[tokio::test]
#[serial]
#[ignore]
async fn settings_requires_auth() {
    let app = TestApp::new().await;

    let resp = app
        .router
        .clone()
        .oneshot(
            Request::builder()
                .uri("/admin/settings")
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
async fn logo_upload_and_serve() {
    let app = TestApp::new().await;

    let boundary = "----testboundary";
    // Minimal valid 1x1 PNG
    let png_bytes: Vec<u8> = vec![
        0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A, // PNG signature
        0x00, 0x00, 0x00, 0x0D, 0x49, 0x48, 0x44, 0x52, // IHDR chunk
        0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x01, // 1x1
        0x08, 0x02, 0x00, 0x00, 0x00, 0x90, 0x77, 0x53, 0xDE, // 8-bit RGB
        0x00, 0x00, 0x00, 0x0C, 0x49, 0x44, 0x41, 0x54, // IDAT chunk
        0x08, 0xD7, 0x63, 0xF8, 0xCF, 0xC0, 0x00, 0x00, 0x00, 0x02, 0x00, 0x01, 0xE2, 0x21, 0xBC,
        0x33, 0x00, 0x00, 0x00, 0x00, 0x49, 0x45, 0x4E, 0x44, // IEND chunk
        0xAE, 0x42, 0x60, 0x82,
    ];
    let body = format!(
        "--{boundary}\r\nContent-Disposition: form-data; name=\"file\"; filename=\"logo.png\"\r\nContent-Type: image/png\r\n\r\n"
    );
    let mut body_bytes = body.into_bytes();
    body_bytes.extend_from_slice(&png_bytes);
    body_bytes.extend_from_slice(format!("\r\n--{boundary}--\r\n").as_bytes());

    let cookie = app.admin_cookie();
    let resp = app
        .router
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::PUT)
                .uri("/admin/settings/logo")
                .header(cookie.0, cookie.1)
                .header(
                    "content-type",
                    format!("multipart/form-data; boundary={boundary}"),
                )
                .body(Body::from(body_bytes))
                .unwrap(),
        )
        .await
        .unwrap();

    assert!(
        resp.status().is_success(),
        "expected success on logo upload, got {}",
        resp.status()
    );

    // GET /settings/logo (public route) and verify 200 with content-type: image/png
    let resp = app
        .router
        .clone()
        .oneshot(
            Request::builder()
                .uri("/settings/logo")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(resp.status(), StatusCode::OK);
    let content_type = resp
        .headers()
        .get("content-type")
        .expect("expected content-type header")
        .to_str()
        .unwrap();
    assert!(
        content_type.contains("image/png"),
        "expected image/png content-type, got {content_type}"
    );

    // DELETE /admin/settings/logo
    let resp = app
        .router
        .clone()
        .oneshot(admin_delete("/admin/settings/logo", app.admin_cookie()))
        .await
        .unwrap();

    assert!(
        resp.status().is_success(),
        "expected success on DELETE logo, got {}",
        resp.status()
    );

    // GET /settings/logo should now return 404
    let resp = app
        .router
        .clone()
        .oneshot(
            Request::builder()
                .uri("/settings/logo")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(resp.status(), StatusCode::NOT_FOUND);
}

#[tokio::test]
#[serial]
#[ignore]
async fn client_metadata_includes_settings() {
    let app = TestApp::new().await;

    // PUT app_name setting
    let resp = app
        .router
        .clone()
        .oneshot(admin_put(
            "/admin/settings/app_name",
            app.admin_cookie(),
            &json!({ "value": "Test App" }),
        ))
        .await
        .unwrap();

    assert!(
        resp.status().is_success(),
        "expected success on PUT app_name, got {}",
        resp.status()
    );

    // GET /oauth-client-metadata.json (no auth) and verify client_name
    let resp = app
        .router
        .clone()
        .oneshot(
            Request::builder()
                .uri("/oauth-client-metadata.json")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(resp.status(), StatusCode::OK);
    let json = json_body(resp).await;
    assert_eq!(
        json["client_name"], "Test App",
        "expected client_name to be 'Test App', got {:?}",
        json["client_name"]
    );
}

#[tokio::test]
#[serial]
#[ignore]
async fn client_metadata_client_id_matches_path() {
    let app = TestApp::new().await;

    let resp = app
        .router
        .clone()
        .oneshot(
            Request::builder()
                .uri("/oauth-client-metadata.json")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let json = json_body(resp).await;
    let client_id = json["client_id"].as_str().expect("client_id missing");
    assert!(
        client_id.ends_with("/oauth-client-metadata.json"),
        "client_id should end with /oauth-client-metadata.json, got {client_id}"
    );
}

#[tokio::test]
#[serial]
#[ignore]
async fn client_metadata_scope_overridden_by_setting() {
    let app = TestApp::new().await;

    let resp = app
        .router
        .clone()
        .oneshot(admin_put(
            "/admin/settings/oauth_scopes",
            app.admin_cookie(),
            &json!({ "value": "atproto  include:com.example.foo\n include:com.example.bar" }),
        ))
        .await
        .unwrap();
    assert!(resp.status().is_success());

    let resp = app
        .router
        .clone()
        .oneshot(
            Request::builder()
                .uri("/oauth-client-metadata.json")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let json = json_body(resp).await;
    assert_eq!(
        json["scope"], "atproto include:com.example.foo include:com.example.bar",
        "expected normalized scope string, got {:?}",
        json["scope"]
    );
}

#[tokio::test]
#[serial]
#[ignore]
async fn client_metadata_client_uri_overridden_by_setting() {
    let app = TestApp::new().await;

    let resp = app
        .router
        .clone()
        .oneshot(admin_put(
            "/admin/settings/client_uri",
            app.admin_cookie(),
            &json!({ "value": "https://example.test" }),
        ))
        .await
        .unwrap();
    assert!(resp.status().is_success());

    let resp = app
        .router
        .clone()
        .oneshot(
            Request::builder()
                .uri("/oauth-client-metadata.json")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let json = json_body(resp).await;
    assert_eq!(
        json["client_uri"], "https://example.test",
        "expected client_uri override, got {:?}",
        json["client_uri"]
    );
}
