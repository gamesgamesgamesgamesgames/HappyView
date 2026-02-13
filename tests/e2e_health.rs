mod common;

use axum::body::Body;
use axum::http::Request;
use http_body_util::BodyExt;
use serial_test::serial;
use tower::ServiceExt;

#[tokio::test]
#[serial]
async fn health_returns_200_ok() {
    let app = common::app::TestApp::new().await;

    let resp = app
        .router
        .oneshot(
            Request::builder()
                .uri("/health")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(resp.status(), 200);
    let body = resp.into_body().collect().await.unwrap().to_bytes();
    assert_eq!(&body[..], b"ok");
}
