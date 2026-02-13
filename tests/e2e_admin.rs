mod common;

use axum::body::Body;
use axum::http::{Request, StatusCode};
use http_body_util::BodyExt;
use serde_json::{Value, json};
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

fn admin_post(uri: &str, token: &str, body: &Value) -> Request<Body> {
    let (hname, hval) = admin_auth_header(token);
    Request::builder()
        .method("POST")
        .uri(uri)
        .header(hname, hval)
        .header("content-type", "application/json")
        .body(Body::from(serde_json::to_vec(body).unwrap()))
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

// ---------------------------------------------------------------------------
// Auth tests
// ---------------------------------------------------------------------------

#[tokio::test]
#[serial]
async fn admin_no_auth_returns_401() {
    let app = TestApp::new().await;

    let resp = app
        .router
        .oneshot(
            Request::builder()
                .uri("/admin/lexicons")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
#[serial]
async fn admin_wrong_token_returns_401() {
    let app = TestApp::new().await;

    let resp = app
        .router
        .oneshot(admin_get("/admin/lexicons", "wrong-token"))
        .await
        .unwrap();

    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
#[serial]
async fn admin_valid_token_returns_200() {
    let app = TestApp::new().await;

    let resp = app
        .router
        .oneshot(admin_get("/admin/lexicons", &app.admin_secret))
        .await
        .unwrap();

    assert_eq!(resp.status(), StatusCode::OK);
}

// ---------------------------------------------------------------------------
// Lexicon CRUD
// ---------------------------------------------------------------------------

#[tokio::test]
#[serial]
async fn lexicon_create_returns_201() {
    let app = TestApp::new().await;
    let body = json!({
        "lexicon_json": fixtures::game_record_lexicon(),
        "backfill": true
    });

    let resp = app
        .router
        .oneshot(admin_post("/admin/lexicons", &app.admin_secret, &body))
        .await
        .unwrap();

    assert_eq!(resp.status(), StatusCode::CREATED);
    let json = json_body(resp).await;
    assert_eq!(json["id"], "games.gamesgamesgamesgames.game");
    assert_eq!(json["revision"], 1);
}

#[tokio::test]
#[serial]
async fn lexicon_upsert_returns_200_with_incremented_revision() {
    let app = TestApp::new().await;
    let body = json!({
        "lexicon_json": fixtures::game_record_lexicon(),
        "backfill": true
    });

    // First create
    let resp = app
        .router
        .clone()
        .oneshot(admin_post("/admin/lexicons", &app.admin_secret, &body))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::CREATED);

    // Upsert
    let resp = app
        .router
        .oneshot(admin_post("/admin/lexicons", &app.admin_secret, &body))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let json = json_body(resp).await;
    assert_eq!(json["revision"], 2);
}

#[tokio::test]
#[serial]
async fn lexicon_invalid_version_returns_400() {
    let app = TestApp::new().await;
    let body = json!({
        "lexicon_json": { "lexicon": 99, "id": "test.bad" },
    });

    let resp = app
        .router
        .oneshot(admin_post("/admin/lexicons", &app.admin_secret, &body))
        .await
        .unwrap();

    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
}

#[tokio::test]
#[serial]
async fn lexicon_missing_id_returns_400() {
    let app = TestApp::new().await;
    let body = json!({
        "lexicon_json": { "lexicon": 1 },
    });

    let resp = app
        .router
        .oneshot(admin_post("/admin/lexicons", &app.admin_secret, &body))
        .await
        .unwrap();

    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
}

#[tokio::test]
#[serial]
async fn lexicon_list_all() {
    let app = TestApp::new().await;

    // Seed a lexicon
    app.router
        .clone()
        .oneshot(admin_post(
            "/admin/lexicons",
            &app.admin_secret,
            &json!({ "lexicon_json": fixtures::game_record_lexicon() }),
        ))
        .await
        .unwrap();

    let resp = app
        .router
        .oneshot(admin_get("/admin/lexicons", &app.admin_secret))
        .await
        .unwrap();

    assert_eq!(resp.status(), StatusCode::OK);
    let json = json_body(resp).await;
    let arr = json.as_array().unwrap();
    assert_eq!(arr.len(), 1);
    assert_eq!(arr[0]["id"], "games.gamesgamesgamesgames.game");
}

#[tokio::test]
#[serial]
async fn lexicon_get_by_id() {
    let app = TestApp::new().await;

    app.router
        .clone()
        .oneshot(admin_post(
            "/admin/lexicons",
            &app.admin_secret,
            &json!({ "lexicon_json": fixtures::game_record_lexicon() }),
        ))
        .await
        .unwrap();

    let resp = app
        .router
        .oneshot(admin_get(
            "/admin/lexicons/games.gamesgamesgamesgames.game",
            &app.admin_secret,
        ))
        .await
        .unwrap();

    assert_eq!(resp.status(), StatusCode::OK);
    let json = json_body(resp).await;
    assert_eq!(json["id"], "games.gamesgamesgamesgames.game");
}

#[tokio::test]
#[serial]
async fn lexicon_get_not_found() {
    let app = TestApp::new().await;

    let resp = app
        .router
        .oneshot(admin_get(
            "/admin/lexicons/nonexistent.lexicon",
            &app.admin_secret,
        ))
        .await
        .unwrap();

    assert_eq!(resp.status(), StatusCode::NOT_FOUND);
}

#[tokio::test]
#[serial]
async fn lexicon_delete() {
    let app = TestApp::new().await;

    app.router
        .clone()
        .oneshot(admin_post(
            "/admin/lexicons",
            &app.admin_secret,
            &json!({ "lexicon_json": fixtures::game_record_lexicon() }),
        ))
        .await
        .unwrap();

    let resp = app
        .router
        .oneshot(admin_delete(
            "/admin/lexicons/games.gamesgamesgamesgames.game",
            &app.admin_secret,
        ))
        .await
        .unwrap();

    assert_eq!(resp.status(), StatusCode::NO_CONTENT);
}

#[tokio::test]
#[serial]
async fn lexicon_delete_not_found() {
    let app = TestApp::new().await;

    let resp = app
        .router
        .oneshot(admin_delete(
            "/admin/lexicons/nonexistent.lexicon",
            &app.admin_secret,
        ))
        .await
        .unwrap();

    assert_eq!(resp.status(), StatusCode::NOT_FOUND);
}

// ---------------------------------------------------------------------------
// Stats
// ---------------------------------------------------------------------------

#[tokio::test]
#[serial]
async fn stats_empty_db() {
    let app = TestApp::new().await;

    let resp = app
        .router
        .oneshot(admin_get("/admin/stats", &app.admin_secret))
        .await
        .unwrap();

    assert_eq!(resp.status(), StatusCode::OK);
    let json = json_body(resp).await;
    assert_eq!(json["total_records"], 0);
    assert!(json["collections"].as_array().unwrap().is_empty());
}

#[tokio::test]
#[serial]
async fn stats_with_seeded_records() {
    let app = TestApp::new().await;

    // Seed records directly
    sqlx::query(
        "INSERT INTO records (uri, did, collection, rkey, record, cid) VALUES ($1, $2, $3, $4, $5, $6)",
    )
    .bind("at://did:plc:test/test.collection/1")
    .bind("did:plc:test")
    .bind("test.collection")
    .bind("1")
    .bind(serde_json::json!({"title": "test"}))
    .bind("bafytest")
    .execute(&app.state.db)
    .await
    .unwrap();

    let resp = app
        .router
        .oneshot(admin_get("/admin/stats", &app.admin_secret))
        .await
        .unwrap();

    assert_eq!(resp.status(), StatusCode::OK);
    let json = json_body(resp).await;
    assert_eq!(json["total_records"], 1);
    assert_eq!(json["collections"][0]["collection"], "test.collection");
    assert_eq!(json["collections"][0]["count"], 1);
}

// ---------------------------------------------------------------------------
// Backfill
// ---------------------------------------------------------------------------

#[tokio::test]
#[serial]
async fn backfill_create_job() {
    let app = TestApp::new().await;
    let body = json!({ "collection": "test.collection" });

    let resp = app
        .router
        .oneshot(admin_post("/admin/backfill", &app.admin_secret, &body))
        .await
        .unwrap();

    assert_eq!(resp.status(), StatusCode::CREATED);
    let json = json_body(resp).await;
    assert_eq!(json["status"], "pending");
    assert!(json.get("id").is_some());
}

#[tokio::test]
#[serial]
async fn backfill_list_jobs() {
    let app = TestApp::new().await;

    // Create a job first
    app.router
        .clone()
        .oneshot(admin_post("/admin/backfill", &app.admin_secret, &json!({})))
        .await
        .unwrap();

    let resp = app
        .router
        .oneshot(admin_get("/admin/backfill/status", &app.admin_secret))
        .await
        .unwrap();

    assert_eq!(resp.status(), StatusCode::OK);
    let json = json_body(resp).await;
    assert_eq!(json.as_array().unwrap().len(), 1);
}

// ---------------------------------------------------------------------------
// Admin management
// ---------------------------------------------------------------------------

#[tokio::test]
#[serial]
async fn admin_create_returns_api_key() {
    let app = TestApp::new().await;
    let body = json!({ "name": "test-admin" });

    let resp = app
        .router
        .oneshot(admin_post("/admin/admins", &app.admin_secret, &body))
        .await
        .unwrap();

    assert_eq!(resp.status(), StatusCode::CREATED);
    let json = json_body(resp).await;
    assert_eq!(json["name"], "test-admin");
    assert!(json.get("api_key").is_some());
    assert!(json.get("id").is_some());
}

#[tokio::test]
#[serial]
async fn admin_created_key_authenticates() {
    let app = TestApp::new().await;
    let body = json!({ "name": "new-admin" });

    // Create admin
    let resp = app
        .router
        .clone()
        .oneshot(admin_post("/admin/admins", &app.admin_secret, &body))
        .await
        .unwrap();
    let json = json_body(resp).await;
    let api_key = json["api_key"].as_str().unwrap();

    // Use the new key
    let resp = app
        .router
        .oneshot(admin_get("/admin/lexicons", api_key))
        .await
        .unwrap();

    assert_eq!(resp.status(), StatusCode::OK);
}

#[tokio::test]
#[serial]
async fn admin_list_excludes_keys() {
    let app = TestApp::new().await;

    let resp = app
        .router
        .oneshot(admin_get("/admin/admins", &app.admin_secret))
        .await
        .unwrap();

    assert_eq!(resp.status(), StatusCode::OK);
    let json = json_body(resp).await;
    let admins = json.as_array().unwrap();
    assert!(!admins.is_empty());
    // No admin should expose api_key or api_key_hash
    for admin in admins {
        assert!(admin.get("api_key").is_none());
        assert!(admin.get("api_key_hash").is_none());
    }
}

#[tokio::test]
#[serial]
async fn admin_delete_returns_204() {
    let app = TestApp::new().await;

    // Create an admin to delete
    let resp = app
        .router
        .clone()
        .oneshot(admin_post(
            "/admin/admins",
            &app.admin_secret,
            &json!({ "name": "disposable" }),
        ))
        .await
        .unwrap();
    let json = json_body(resp).await;
    let id = json["id"].as_str().unwrap();

    let resp = app
        .router
        .oneshot(admin_delete(
            &format!("/admin/admins/{id}"),
            &app.admin_secret,
        ))
        .await
        .unwrap();

    assert_eq!(resp.status(), StatusCode::NO_CONTENT);
}

#[tokio::test]
#[serial]
async fn admin_delete_not_found() {
    let app = TestApp::new().await;

    let resp = app
        .router
        .oneshot(admin_delete(
            "/admin/admins/00000000-0000-0000-0000-000000000000",
            &app.admin_secret,
        ))
        .await
        .unwrap();

    assert_eq!(resp.status(), StatusCode::NOT_FOUND);
}
