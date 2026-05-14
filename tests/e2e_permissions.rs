mod common;

use axum::body::Body;
use axum::http::{Method, Request, StatusCode};
use http_body_util::BodyExt;
use serde_json::{Value, json};
use serial_test::serial;
use tower::ServiceExt;

use common::app::TestApp;

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

#[tokio::test]
#[serial]
async fn permissions_requires_auth() {
    common::require_db!();
    let app = TestApp::new().await;

    let resp = app
        .router
        .clone()
        .oneshot(
            Request::builder()
                .uri("/admin/permissions")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
#[serial]
async fn permissions_returns_catalog() {
    common::require_db!();
    let app = TestApp::new().await;

    let resp = app
        .router
        .clone()
        .oneshot(admin_get("/admin/permissions", app.admin_cookie()))
        .await
        .unwrap();

    assert_eq!(resp.status(), StatusCode::OK);
    let body = json_body(resp).await;

    let permissions = body["permissions"].as_array().expect("permissions array");
    assert!(!permissions.is_empty());

    let first = &permissions[0];
    assert!(first["key"].is_string());
    assert!(first["name"].is_string());
    assert!(first["description"].is_string());
    assert!(first["category"].is_string());

    let templates = body["templates"].as_array().expect("templates array");
    assert!(!templates.is_empty());

    let first_template = &templates[0];
    assert!(first_template["key"].is_string());
    assert!(first_template["label"].is_string());
    assert!(first_template["permissions"].is_array());
}

#[tokio::test]
#[serial]
async fn permissions_excludes_spaces_when_flag_disabled() {
    common::require_db!();
    let app = TestApp::new().await;

    let resp = app
        .router
        .clone()
        .oneshot(admin_get("/admin/permissions", app.admin_cookie()))
        .await
        .unwrap();

    assert_eq!(resp.status(), StatusCode::OK);
    let body = json_body(resp).await;

    let permissions = body["permissions"].as_array().unwrap();
    let has_spaces = permissions
        .iter()
        .any(|p| p["key"].as_str().unwrap_or("").starts_with("spaces:"));
    assert!(
        !has_spaces,
        "spaces permissions should be excluded when flag is disabled"
    );

    let has_spaces_category = permissions
        .iter()
        .any(|p| p["category"].as_str().unwrap_or("") == "Spaces");
    assert!(
        !has_spaces_category,
        "Spaces category should not appear when flag is disabled"
    );

    let templates = body["templates"].as_array().unwrap();
    for template in templates {
        let perms = template["permissions"].as_array().unwrap();
        let has_spaces_perm = perms
            .iter()
            .any(|p| p.as_str().unwrap_or("").starts_with("spaces:"));
        assert!(
            !has_spaces_perm,
            "template {:?} should not contain spaces permissions when flag is disabled",
            template["key"]
        );
    }
}

#[tokio::test]
#[serial]
async fn permissions_includes_spaces_when_flag_enabled() {
    common::require_db!();
    let app = TestApp::new().await;

    // Enable the spaces feature flag
    let resp = app
        .router
        .clone()
        .oneshot(admin_put(
            "/admin/settings/feature.spaces_enabled",
            app.admin_cookie(),
            &json!({ "value": "true" }),
        ))
        .await
        .unwrap();
    assert!(resp.status().is_success());

    let resp = app
        .router
        .clone()
        .oneshot(admin_get("/admin/permissions", app.admin_cookie()))
        .await
        .unwrap();

    assert_eq!(resp.status(), StatusCode::OK);
    let body = json_body(resp).await;

    let permissions = body["permissions"].as_array().unwrap();
    let has_spaces = permissions
        .iter()
        .any(|p| p["key"].as_str().unwrap_or("").starts_with("spaces:"));
    assert!(
        has_spaces,
        "spaces permissions should be included when flag is enabled"
    );

    let templates = body["templates"].as_array().unwrap();
    let manager = templates
        .iter()
        .find(|t| t["key"] == "manager")
        .expect("manager template");
    let manager_perms = manager["permissions"].as_array().unwrap();
    let has_spaces_perm = manager_perms
        .iter()
        .any(|p| p.as_str().unwrap_or("").starts_with("spaces:"));
    assert!(
        has_spaces_perm,
        "manager template should include spaces permissions when flag is enabled"
    );
}

#[tokio::test]
#[serial]
async fn permissions_spaces_removed_after_disabling_flag() {
    common::require_db!();
    let app = TestApp::new().await;

    // Enable
    let resp = app
        .router
        .clone()
        .oneshot(admin_put(
            "/admin/settings/feature.spaces_enabled",
            app.admin_cookie(),
            &json!({ "value": "true" }),
        ))
        .await
        .unwrap();
    assert!(resp.status().is_success());

    // Disable
    let resp = app
        .router
        .clone()
        .oneshot(admin_delete(
            "/admin/settings/feature.spaces_enabled",
            app.admin_cookie(),
        ))
        .await
        .unwrap();
    assert!(resp.status().is_success());

    let resp = app
        .router
        .clone()
        .oneshot(admin_get("/admin/permissions", app.admin_cookie()))
        .await
        .unwrap();

    assert_eq!(resp.status(), StatusCode::OK);
    let body = json_body(resp).await;

    let permissions = body["permissions"].as_array().unwrap();
    let has_spaces = permissions
        .iter()
        .any(|p| p["key"].as_str().unwrap_or("").starts_with("spaces:"));
    assert!(
        !has_spaces,
        "spaces permissions should be gone after disabling flag"
    );
}
