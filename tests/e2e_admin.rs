mod common;

use axum::body::Body;
use axum::http::{Request, StatusCode};
use happyview::db::{adapt_sql, now_rfc3339};
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
#[ignore]
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
#[ignore]
async fn admin_wrong_token_returns_401() {
    let app = TestApp::new().await;

    // No AIP mock mounted — the userinfo request will fail.
    let resp = app
        .router
        .oneshot(admin_get("/admin/lexicons", "wrong-token"))
        .await
        .unwrap();

    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
#[serial]
#[ignore]
async fn admin_valid_token_returns_200() {
    let app = TestApp::new().await;
    app.mock_admin_userinfo().await;

    let resp = app
        .router
        .oneshot(admin_get("/admin/lexicons", &app.admin_token))
        .await
        .unwrap();

    assert_eq!(resp.status(), StatusCode::OK);
}

#[tokio::test]
#[serial]
#[ignore]
async fn admin_non_admin_did_returns_403() {
    let app = TestApp::new().await;

    // Mock AIP returning a DID that is NOT in the admins table.
    common::auth::mock_aip_userinfo(&app.mock_server, "did:plc:notadmin").await;

    let resp = app
        .router
        .oneshot(admin_get("/admin/lexicons", "some-token"))
        .await
        .unwrap();

    assert_eq!(resp.status(), StatusCode::FORBIDDEN);
}

#[tokio::test]
#[serial]
#[ignore]
async fn admin_auto_bootstrap_first_user() {
    let app = TestApp::new().await;
    let backend = app.state.db_backend;

    // Clear the seeded user so the table is empty.
    sqlx::query("DELETE FROM users")
        .execute(&app.state.db)
        .await
        .unwrap();

    // Mock AIP returning a new DID.
    let bootstrap_did = "did:plc:bootstrap";
    common::auth::mock_aip_userinfo(&app.mock_server, bootstrap_did).await;

    let resp = app
        .router
        .oneshot(admin_get("/admin/lexicons", "bootstrap-token"))
        .await
        .unwrap();

    // The first user should be auto-bootstrapped as admin.
    assert_eq!(resp.status(), StatusCode::OK);

    // Verify the DID was inserted.
    let sql = adapt_sql("SELECT COUNT(*) FROM users WHERE did = $1", backend);
    let count: (i64,) = sqlx::query_as(&sql)
        .bind(bootstrap_did)
        .fetch_one(&app.state.db)
        .await
        .unwrap();
    assert_eq!(count.0, 1);
}

// ---------------------------------------------------------------------------
// Lexicon CRUD
// ---------------------------------------------------------------------------

#[tokio::test]
#[serial]
#[ignore]
async fn lexicon_create_returns_201() {
    let app = TestApp::new().await;
    app.mock_admin_userinfo().await;
    let body = json!({
        "lexicon_json": fixtures::game_record_lexicon(),
        "backfill": true
    });

    let resp = app
        .router
        .oneshot(admin_post("/admin/lexicons", &app.admin_token, &body))
        .await
        .unwrap();

    assert_eq!(resp.status(), StatusCode::CREATED);
    let json = json_body(resp).await;
    assert_eq!(json["id"], "games.gamesgamesgamesgames.game");
    assert_eq!(json["revision"], 1);
}

#[tokio::test]
#[serial]
#[ignore]
async fn lexicon_upsert_returns_200_with_incremented_revision() {
    let app = TestApp::new().await;
    app.mock_admin_userinfo().await;
    let body = json!({
        "lexicon_json": fixtures::game_record_lexicon(),
        "backfill": true
    });

    // First create
    let resp = app
        .router
        .clone()
        .oneshot(admin_post("/admin/lexicons", &app.admin_token, &body))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::CREATED);

    // Upsert
    let resp = app
        .router
        .oneshot(admin_post("/admin/lexicons", &app.admin_token, &body))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let json = json_body(resp).await;
    assert_eq!(json["revision"], 2);
}

#[tokio::test]
#[serial]
#[ignore]
async fn lexicon_invalid_version_returns_400() {
    let app = TestApp::new().await;
    app.mock_admin_userinfo().await;
    let body = json!({
        "lexicon_json": { "lexicon": 99, "id": "test.bad" },
    });

    let resp = app
        .router
        .oneshot(admin_post("/admin/lexicons", &app.admin_token, &body))
        .await
        .unwrap();

    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
}

#[tokio::test]
#[serial]
#[ignore]
async fn lexicon_missing_id_returns_400() {
    let app = TestApp::new().await;
    app.mock_admin_userinfo().await;
    let body = json!({
        "lexicon_json": { "lexicon": 1 },
    });

    let resp = app
        .router
        .oneshot(admin_post("/admin/lexicons", &app.admin_token, &body))
        .await
        .unwrap();

    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
}

#[tokio::test]
#[serial]
#[ignore]
async fn lexicon_list_all() {
    let app = TestApp::new().await;
    app.mock_admin_userinfo().await;

    // Seed a lexicon
    app.router
        .clone()
        .oneshot(admin_post(
            "/admin/lexicons",
            &app.admin_token,
            &json!({ "lexicon_json": fixtures::game_record_lexicon() }),
        ))
        .await
        .unwrap();

    let resp = app
        .router
        .oneshot(admin_get("/admin/lexicons", &app.admin_token))
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
#[ignore]
async fn lexicon_get_by_id() {
    let app = TestApp::new().await;
    app.mock_admin_userinfo().await;

    app.router
        .clone()
        .oneshot(admin_post(
            "/admin/lexicons",
            &app.admin_token,
            &json!({ "lexicon_json": fixtures::game_record_lexicon() }),
        ))
        .await
        .unwrap();

    let resp = app
        .router
        .oneshot(admin_get(
            "/admin/lexicons/games.gamesgamesgamesgames.game",
            &app.admin_token,
        ))
        .await
        .unwrap();

    assert_eq!(resp.status(), StatusCode::OK);
    let json = json_body(resp).await;
    assert_eq!(json["id"], "games.gamesgamesgamesgames.game");
}

#[tokio::test]
#[serial]
#[ignore]
async fn lexicon_get_not_found() {
    let app = TestApp::new().await;
    app.mock_admin_userinfo().await;

    let resp = app
        .router
        .oneshot(admin_get(
            "/admin/lexicons/nonexistent.lexicon",
            &app.admin_token,
        ))
        .await
        .unwrap();

    assert_eq!(resp.status(), StatusCode::NOT_FOUND);
}

#[tokio::test]
#[serial]
#[ignore]
async fn lexicon_delete() {
    let app = TestApp::new().await;
    app.mock_admin_userinfo().await;

    app.router
        .clone()
        .oneshot(admin_post(
            "/admin/lexicons",
            &app.admin_token,
            &json!({ "lexicon_json": fixtures::game_record_lexicon() }),
        ))
        .await
        .unwrap();

    let resp = app
        .router
        .oneshot(admin_delete(
            "/admin/lexicons/games.gamesgamesgamesgames.game",
            &app.admin_token,
        ))
        .await
        .unwrap();

    assert_eq!(resp.status(), StatusCode::NO_CONTENT);
}

#[tokio::test]
#[serial]
#[ignore]
async fn lexicon_delete_not_found() {
    let app = TestApp::new().await;
    app.mock_admin_userinfo().await;

    let resp = app
        .router
        .oneshot(admin_delete(
            "/admin/lexicons/nonexistent.lexicon",
            &app.admin_token,
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
#[ignore]
async fn stats_empty_db() {
    let app = TestApp::new().await;
    app.mock_admin_userinfo().await;

    let resp = app
        .router
        .oneshot(admin_get("/admin/stats", &app.admin_token))
        .await
        .unwrap();

    assert_eq!(resp.status(), StatusCode::OK);
    let json = json_body(resp).await;
    assert_eq!(json["total_records"], 0);
    assert!(json["collections"].as_array().unwrap().is_empty());
}

#[tokio::test]
#[serial]
#[ignore]
async fn stats_with_seeded_records() {
    let app = TestApp::new().await;
    app.mock_admin_userinfo().await;
    let backend = app.state.db_backend;

    // Seed a lexicon so the stats query can join against it
    let lexicon_json_val = serde_json::json!({
        "lexicon": 1,
        "id": "test.collection",
        "defs": { "main": { "type": "record", "key": "tid", "record": { "type": "object", "properties": {} } } }
    });
    let now = now_rfc3339();
    let sql = adapt_sql(
        "INSERT INTO lexicons (id, lexicon_json, created_at) VALUES ($1, $2, $3)",
        backend,
    );
    sqlx::query(&sql)
        .bind("test.collection")
        .bind(serde_json::to_string(&lexicon_json_val).unwrap_or_default())
        .bind(&now)
        .execute(&app.state.db)
        .await
        .unwrap();

    // Seed records directly
    let record_val = serde_json::json!({"title": "test"});
    let sql = adapt_sql(
        "INSERT INTO records (uri, did, collection, rkey, record, cid, created_at) VALUES ($1, $2, $3, $4, $5, $6, $7)",
        backend,
    );
    sqlx::query(&sql)
        .bind("at://did:plc:test/test.collection/1")
        .bind("did:plc:test")
        .bind("test.collection")
        .bind("1")
        .bind(serde_json::to_string(&record_val).unwrap_or_default())
        .bind("bafytest")
        .bind(&now)
        .execute(&app.state.db)
        .await
        .unwrap();

    let resp = app
        .router
        .oneshot(admin_get("/admin/stats", &app.admin_token))
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
#[ignore]
async fn backfill_create_job() {
    let app = TestApp::new().await;
    app.mock_admin_userinfo().await;

    // Register a record-type lexicon first (required by backfill validation).
    let lexicon_body = json!({
        "lexicon_json": fixtures::game_record_lexicon(),
        "backfill": true
    });
    app.router
        .clone()
        .oneshot(admin_post(
            "/admin/lexicons",
            &app.admin_token,
            &lexicon_body,
        ))
        .await
        .unwrap();

    let body = json!({ "collection": "games.gamesgamesgamesgames.game" });

    let resp = app
        .router
        .oneshot(admin_post("/admin/backfill", &app.admin_token, &body))
        .await
        .unwrap();

    assert_eq!(resp.status(), StatusCode::CREATED);
    let json = json_body(resp).await;
    assert_eq!(json["status"], "completed");
    assert!(json.get("id").is_some());
}

#[tokio::test]
#[serial]
#[ignore]
async fn backfill_list_jobs() {
    let app = TestApp::new().await;
    app.mock_admin_userinfo().await;

    // Create a job first
    app.router
        .clone()
        .oneshot(admin_post("/admin/backfill", &app.admin_token, &json!({})))
        .await
        .unwrap();

    let resp = app
        .router
        .oneshot(admin_get("/admin/backfill/status", &app.admin_token))
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
#[ignore]
async fn admin_create_returns_did() {
    let app = TestApp::new().await;
    app.mock_admin_userinfo().await;
    let body = json!({ "did": "did:plc:newadmin" });

    let resp = app
        .router
        .oneshot(admin_post("/admin/users", &app.admin_token, &body))
        .await
        .unwrap();

    assert_eq!(resp.status(), StatusCode::CREATED);
    let json = json_body(resp).await;
    assert_eq!(json["did"], "did:plc:newadmin");
    assert!(json.get("id").is_some());
}

#[tokio::test]
#[serial]
#[ignore]
async fn admin_created_did_authenticates() {
    let app = TestApp::new().await;
    app.mock_admin_userinfo().await;

    let new_did = "did:plc:newadmin2";
    let body = json!({ "did": new_did });

    // Create admin via the existing admin
    app.router
        .clone()
        .oneshot(admin_post("/admin/users", &app.admin_token, &body))
        .await
        .unwrap();

    // Now mock AIP returning the new DID for a different token
    common::auth::mock_aip_userinfo(&app.mock_server, new_did).await;

    let resp = app
        .router
        .oneshot(admin_get("/admin/lexicons", "new-admin-token"))
        .await
        .unwrap();

    assert_eq!(resp.status(), StatusCode::OK);
}

#[tokio::test]
#[serial]
#[ignore]
async fn admin_list_returns_dids() {
    let app = TestApp::new().await;
    app.mock_admin_userinfo().await;

    let resp = app
        .router
        .oneshot(admin_get("/admin/users", &app.admin_token))
        .await
        .unwrap();

    assert_eq!(resp.status(), StatusCode::OK);
    let json = json_body(resp).await;
    let admins = json.as_array().unwrap();
    assert!(!admins.is_empty());
    for admin in admins {
        assert!(admin.get("did").is_some());
        assert!(admin.get("api_key").is_none());
        assert!(admin.get("api_key_hash").is_none());
    }
}

#[tokio::test]
#[serial]
#[ignore]
async fn admin_delete_returns_204() {
    let app = TestApp::new().await;
    app.mock_admin_userinfo().await;

    // Create an admin to delete
    let resp = app
        .router
        .clone()
        .oneshot(admin_post(
            "/admin/users",
            &app.admin_token,
            &json!({ "did": "did:plc:disposable" }),
        ))
        .await
        .unwrap();
    let json = json_body(resp).await;
    let id = json["id"].as_str().unwrap();

    let resp = app
        .router
        .oneshot(admin_delete(
            &format!("/admin/users/{id}"),
            &app.admin_token,
        ))
        .await
        .unwrap();

    assert_eq!(resp.status(), StatusCode::NO_CONTENT);
}

#[tokio::test]
#[serial]
#[ignore]
async fn admin_delete_not_found() {
    let app = TestApp::new().await;
    app.mock_admin_userinfo().await;

    let resp = app
        .router
        .oneshot(admin_delete(
            "/admin/users/00000000-0000-0000-0000-000000000000",
            &app.admin_token,
        ))
        .await
        .unwrap();

    assert_eq!(resp.status(), StatusCode::NOT_FOUND);
}
