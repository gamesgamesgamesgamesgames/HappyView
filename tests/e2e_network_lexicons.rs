mod common;

use axum::body::Body;
use axum::http::{Request, StatusCode};
use http_body_util::BodyExt;
use serde_json::Value;
use serial_test::serial;
use tower::ServiceExt;

use common::app::TestApp;
use common::auth::admin_auth_header;
use common::fixtures;

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

async fn json_body(resp: axum::response::Response) -> Value {
    let body = resp.into_body().collect().await.unwrap().to_bytes();
    serde_json::from_slice(&body).unwrap()
}

fn admin_get(uri: &str, token: &str) -> Request<Body> {
    let (hname, hval) = admin_auth_header(token);
    Request::builder()
        .uri(uri)
        .header(hname, hval)
        .body(Body::empty())
        .unwrap()
}

fn admin_delete(uri: &str, token: &str) -> Request<Body> {
    let (hname, hval) = admin_auth_header(token);
    Request::builder()
        .method("DELETE")
        .uri(uri)
        .header(hname, hval)
        .body(Body::empty())
        .unwrap()
}

/// Set up mocks for NSID authority resolution:
/// - DNS TXT is not mockable in e2e, so we test at the API level by mocking
///   the PLC directory and PDS responses and seeding the network_lexicons table directly.
async fn seed_network_lexicon(app: &TestApp, nsid: &str, authority_did: &str) {
    sqlx::query(
        r#"
        INSERT INTO network_lexicons (nsid, authority_did, last_fetched_at)
        VALUES ($1, $2, NOW())
        ON CONFLICT (nsid) DO NOTHING
        "#,
    )
    .bind(nsid)
    .bind(authority_did)
    .execute(&app.state.db)
    .await
    .expect("failed to seed network lexicon");

    // Also seed the lexicons table so it's consistent.
    let lexicon_json = fixtures::game_record_lexicon();
    sqlx::query(
        r#"
        INSERT INTO lexicons (id, lexicon_json, backfill)
        VALUES ($1, $2, false)
        ON CONFLICT (id) DO NOTHING
        "#,
    )
    .bind(nsid)
    .bind(&lexicon_json)
    .execute(&app.state.db)
    .await
    .expect("failed to seed lexicon");
}

// ---------------------------------------------------------------------------
// Network lexicon CRUD
// ---------------------------------------------------------------------------

#[tokio::test]
#[serial]
async fn network_lexicon_list_empty() {
    let app = TestApp::new().await;
    app.mock_admin_userinfo().await;

    let resp = app
        .router
        .oneshot(admin_get("/admin/network-lexicons", &app.admin_token))
        .await
        .unwrap();

    assert_eq!(resp.status(), StatusCode::OK);
    let json = json_body(resp).await;
    assert!(json.as_array().unwrap().is_empty());
}

#[tokio::test]
#[serial]
async fn network_lexicon_list_returns_seeded() {
    let app = TestApp::new().await;
    app.mock_admin_userinfo().await;

    seed_network_lexicon(&app, "games.gamesgamesgamesgames.game", "did:plc:authority").await;

    let resp = app
        .router
        .oneshot(admin_get("/admin/network-lexicons", &app.admin_token))
        .await
        .unwrap();

    assert_eq!(resp.status(), StatusCode::OK);
    let json = json_body(resp).await;
    let arr = json.as_array().unwrap();
    assert_eq!(arr.len(), 1);
    assert_eq!(arr[0]["nsid"], "games.gamesgamesgamesgames.game");
    assert_eq!(arr[0]["authority_did"], "did:plc:authority");
}

#[tokio::test]
#[serial]
async fn network_lexicon_delete_removes_tracking_and_lexicon() {
    let app = TestApp::new().await;
    app.mock_admin_userinfo().await;

    let nsid = "games.gamesgamesgamesgames.game";
    seed_network_lexicon(&app, nsid, "did:plc:authority").await;

    let resp = app
        .router
        .clone()
        .oneshot(admin_delete(
            &format!("/admin/network-lexicons/{nsid}"),
            &app.admin_token,
        ))
        .await
        .unwrap();

    assert_eq!(resp.status(), StatusCode::NO_CONTENT);

    // Verify network_lexicons table is empty.
    let count: (i64,) = sqlx::query_as("SELECT COUNT(*) FROM network_lexicons WHERE nsid = $1")
        .bind(nsid)
        .fetch_one(&app.state.db)
        .await
        .unwrap();
    assert_eq!(count.0, 0);

    // Verify lexicons table is also cleaned up.
    let count: (i64,) = sqlx::query_as("SELECT COUNT(*) FROM lexicons WHERE id = $1")
        .bind(nsid)
        .fetch_one(&app.state.db)
        .await
        .unwrap();
    assert_eq!(count.0, 0);
}

#[tokio::test]
#[serial]
async fn network_lexicon_delete_not_found() {
    let app = TestApp::new().await;
    app.mock_admin_userinfo().await;

    let resp = app
        .router
        .oneshot(admin_delete(
            "/admin/network-lexicons/nonexistent.lexicon",
            &app.admin_token,
        ))
        .await
        .unwrap();

    assert_eq!(resp.status(), StatusCode::NOT_FOUND);
}

#[tokio::test]
#[serial]
async fn network_lexicon_no_auth_returns_401() {
    let app = TestApp::new().await;

    let resp = app
        .router
        .oneshot(
            Request::builder()
                .uri("/admin/network-lexicons")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
}
