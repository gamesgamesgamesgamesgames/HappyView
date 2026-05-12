mod common;

use axum::body::Body;
use axum::http::{Request, StatusCode, header};
use http_body_util::BodyExt;
use serial_test::serial;
use tower::ServiceExt;

#[tokio::test]
#[serial]
async fn health_at_root_when_base_path_set() {
    common::require_db!();
    let app = common::app::TestApp::new_with_base_path("/hv").await;

    let resp = app
        .router
        .clone()
        .oneshot(
            Request::builder()
                .uri("/health")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(resp.status(), StatusCode::OK);
    let body = resp.into_body().collect().await.unwrap().to_bytes();
    assert_eq!(&body[..], b"ok");
}

#[tokio::test]
#[serial]
async fn health_not_nested_under_base_path() {
    common::require_db!();
    let app = common::app::TestApp::new_with_base_path("/hv").await;

    let resp = app
        .router
        .clone()
        .oneshot(
            Request::builder()
                .uri("/hv/health")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_ne!(resp.status(), StatusCode::OK);
}

#[tokio::test]
#[serial]
async fn config_accessible_under_base_path() {
    common::require_db!();
    let app = common::app::TestApp::new_with_base_path("/hv").await;

    let resp = app
        .router
        .clone()
        .oneshot(
            Request::builder()
                .uri("/hv/config")
                .header("host", "127.0.0.1")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(resp.status(), StatusCode::OK);
}

#[tokio::test]
#[serial]
async fn config_not_at_root_when_base_path_set() {
    common::require_db!();
    let app = common::app::TestApp::new_with_base_path("/hv").await;

    let resp = app
        .router
        .clone()
        .oneshot(
            Request::builder()
                .uri("/config")
                .header("host", "127.0.0.1")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_ne!(resp.status(), StatusCode::OK);
}

#[tokio::test]
#[serial]
async fn redirect_includes_base_path_prefix() {
    common::require_db!();
    let app = common::app::TestApp::new_with_base_path("/hv").await;

    let resp = app
        .router
        .clone()
        .oneshot(
            Request::builder()
                .uri("/hv/login")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    if resp.status().is_redirection() {
        let location = resp
            .headers()
            .get(header::LOCATION)
            .expect("redirect should have Location header")
            .to_str()
            .unwrap();
        assert!(
            location.starts_with("/hv"),
            "redirect Location should include base path, got: {location}"
        );
    }
}
