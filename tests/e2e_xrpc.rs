mod common;

use axum::body::Body;
use axum::http::{Request, StatusCode};
use http_body_util::BodyExt;
use serde_json::{Value, json};
use serial_test::serial;
use tower::ServiceExt;
use wiremock::matchers::{method, path, path_regex};
use wiremock::{Mock, ResponseTemplate};

use common::app::TestApp;
use common::auth::{admin_auth_header, mock_aip_userinfo};
use common::fixtures;

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

async fn json_body(resp: axum::response::Response) -> Value {
    let body = resp.into_body().collect().await.unwrap().to_bytes();
    serde_json::from_slice(&body).unwrap()
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

fn authed_get(uri: &str, token: &str) -> Request<Body> {
    Request::builder()
        .uri(uri)
        .header("authorization", format!("Bearer {token}"))
        .body(Body::empty())
        .unwrap()
}

/// Seed the game record lexicon and a query lexicon into the test app.
async fn seed_lexicons(app: &TestApp) {
    // Record lexicon
    app.router
        .clone()
        .oneshot(admin_post(
            "/admin/lexicons",
            &app.admin_secret,
            &json!({
                "lexicon_json": fixtures::game_record_lexicon(),
                "backfill": false
            }),
        ))
        .await
        .unwrap();

    // Query lexicon
    app.router
        .clone()
        .oneshot(admin_post(
            "/admin/lexicons",
            &app.admin_secret,
            &json!({
                "lexicon_json": fixtures::list_games_query_lexicon(),
                "target_collection": "games.gamesgamesgamesgames.game"
            }),
        ))
        .await
        .unwrap();

    // Procedure lexicon
    app.router
        .clone()
        .oneshot(admin_post(
            "/admin/lexicons",
            &app.admin_secret,
            &json!({
                "lexicon_json": fixtures::create_game_procedure_lexicon(),
                "target_collection": "games.gamesgamesgamesgames.game"
            }),
        ))
        .await
        .unwrap();
}

/// Seed a record directly into the database.
async fn seed_record(app: &TestApp, uri: &str, did: &str, collection: &str, record: &Value) {
    let rkey = uri.split('/').next_back().unwrap_or("1");
    sqlx::query(
        "INSERT INTO records (uri, did, collection, rkey, record, cid) VALUES ($1, $2, $3, $4, $5, $6)",
    )
    .bind(uri)
    .bind(did)
    .bind(collection)
    .bind(rkey)
    .bind(record)
    .bind("bafytest")
    .execute(&app.state.db)
    .await
    .unwrap();
}

// ---------------------------------------------------------------------------
// Profile
// ---------------------------------------------------------------------------

#[tokio::test]
#[serial]
async fn profile_no_auth_returns_401() {
    let app = TestApp::new().await;

    let resp = app
        .router
        .oneshot(
            Request::builder()
                .uri("/xrpc/app.bsky.actor.getProfile")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
#[serial]
async fn profile_with_mocked_services_returns_200() {
    let app = TestApp::new().await;
    let did = "did:plc:testuser";

    // Mock AIP userinfo
    mock_aip_userinfo(&app.mock_server, did).await;

    // Mock PLC directory
    Mock::given(method("GET"))
        .and(path(format!("/{did}")))
        .respond_with(
            ResponseTemplate::new(200)
                .set_body_json(fixtures::did_document(did, &app.mock_server.uri())),
        )
        .mount(&app.mock_server)
        .await;

    // Mock PDS getRecord for profile
    Mock::given(method("GET"))
        .and(path("/xrpc/com.atproto.repo.getRecord"))
        .respond_with(ResponseTemplate::new(200).set_body_json(fixtures::profile_record()))
        .mount(&app.mock_server)
        .await;

    let resp = app
        .router
        .oneshot(authed_get("/xrpc/app.bsky.actor.getProfile", "valid-token"))
        .await
        .unwrap();

    assert_eq!(resp.status(), StatusCode::OK);
    let json = json_body(resp).await;
    assert_eq!(json["did"], did);
    assert_eq!(json["displayName"], "Test User");
}

// ---------------------------------------------------------------------------
// Catch-all GET (queries)
// ---------------------------------------------------------------------------

#[tokio::test]
#[serial]
async fn xrpc_get_unknown_method_returns_400() {
    let app = TestApp::new().await;

    let resp = app
        .router
        .oneshot(
            Request::builder()
                .uri("/xrpc/nonexistent.method")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
}

#[tokio::test]
#[serial]
async fn xrpc_get_non_query_returns_400() {
    let app = TestApp::new().await;
    seed_lexicons(&app).await;

    // game is a record, not a query
    let resp = app
        .router
        .oneshot(
            Request::builder()
                .uri("/xrpc/games.gamesgamesgamesgames.game")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
}

#[tokio::test]
#[serial]
async fn xrpc_get_single_record_by_uri() {
    let app = TestApp::new().await;
    seed_lexicons(&app).await;

    let did = "did:plc:test";
    let uri = "at://did:plc:test/games.gamesgamesgamesgames.game/abc123";
    let record = json!({"title": "Test Game", "$type": "games.gamesgamesgamesgames.game"});
    seed_record(&app, uri, did, "games.gamesgamesgamesgames.game", &record).await;

    // Mock PLC for PDS resolution
    Mock::given(method("GET"))
        .and(path(format!("/{did}")))
        .respond_with(
            ResponseTemplate::new(200)
                .set_body_json(fixtures::did_document(did, "https://pds.example.com")),
        )
        .mount(&app.mock_server)
        .await;

    let resp = app
        .router
        .oneshot(
            Request::builder()
                .uri(format!(
                    "/xrpc/games.gamesgamesgamesgames.listGames?uri={}",
                    urlencoding::encode(uri)
                ))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(resp.status(), StatusCode::OK);
    let json = json_body(resp).await;
    assert_eq!(json["record"]["title"], "Test Game");
    assert_eq!(json["record"]["uri"], uri);
}

#[tokio::test]
#[serial]
async fn xrpc_get_record_not_found() {
    let app = TestApp::new().await;
    seed_lexicons(&app).await;

    let resp = app
        .router
        .oneshot(
            Request::builder()
                .uri("/xrpc/games.gamesgamesgamesgames.listGames?uri=at%3A%2F%2Fdid%3Aplc%3Anone%2Fgames.gamesgamesgamesgames.game%2Fmissing")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(resp.status(), StatusCode::NOT_FOUND);
}

#[tokio::test]
#[serial]
async fn xrpc_get_list_with_pagination() {
    let app = TestApp::new().await;
    seed_lexicons(&app).await;

    let did = "did:plc:test";

    // Mock PLC for enrichment
    Mock::given(method("GET"))
        .and(path_regex("/did:plc:.*"))
        .respond_with(
            ResponseTemplate::new(200)
                .set_body_json(fixtures::did_document(did, "https://pds.example.com")),
        )
        .mount(&app.mock_server)
        .await;

    // Seed 3 records
    for i in 1..=3 {
        let uri = format!("at://{did}/games.gamesgamesgamesgames.game/rec{i}");
        seed_record(
            &app,
            &uri,
            did,
            "games.gamesgamesgamesgames.game",
            &json!({"title": format!("Game {i}")}),
        )
        .await;
    }

    // Request with limit=2
    let resp = app
        .router
        .clone()
        .oneshot(
            Request::builder()
                .uri("/xrpc/games.gamesgamesgamesgames.listGames?limit=2")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(resp.status(), StatusCode::OK);
    let json = json_body(resp).await;
    assert_eq!(json["records"].as_array().unwrap().len(), 2);
    assert!(json.get("cursor").is_some());

    // Use cursor for next page
    let cursor = json["cursor"].as_str().unwrap();
    let resp = app
        .router
        .oneshot(
            Request::builder()
                .uri(format!(
                    "/xrpc/games.gamesgamesgamesgames.listGames?limit=2&cursor={cursor}"
                ))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(resp.status(), StatusCode::OK);
    let json = json_body(resp).await;
    assert_eq!(json["records"].as_array().unwrap().len(), 1);
    assert!(json.get("cursor").is_none());
}

#[tokio::test]
#[serial]
async fn xrpc_get_list_filtered_by_did() {
    let app = TestApp::new().await;
    seed_lexicons(&app).await;

    // Mock PLC
    Mock::given(method("GET"))
        .and(path_regex("/did:plc:.*"))
        .respond_with(
            ResponseTemplate::new(200).set_body_json(fixtures::did_document(
                "did:plc:a",
                "https://pds.example.com",
            )),
        )
        .mount(&app.mock_server)
        .await;

    // Seed records for two different DIDs
    seed_record(
        &app,
        "at://did:plc:a/games.gamesgamesgamesgames.game/1",
        "did:plc:a",
        "games.gamesgamesgamesgames.game",
        &json!({"title": "Game A"}),
    )
    .await;
    seed_record(
        &app,
        "at://did:plc:b/games.gamesgamesgamesgames.game/2",
        "did:plc:b",
        "games.gamesgamesgamesgames.game",
        &json!({"title": "Game B"}),
    )
    .await;

    let resp = app
        .router
        .oneshot(
            Request::builder()
                .uri("/xrpc/games.gamesgamesgamesgames.listGames?did=did:plc:a")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(resp.status(), StatusCode::OK);
    let json = json_body(resp).await;
    let records = json["records"].as_array().unwrap();
    assert_eq!(records.len(), 1);
    assert_eq!(records[0]["title"], "Game A");
}

// ---------------------------------------------------------------------------
// Catch-all POST (procedures)
// ---------------------------------------------------------------------------

#[tokio::test]
#[serial]
async fn xrpc_post_no_auth_returns_401() {
    let app = TestApp::new().await;
    seed_lexicons(&app).await;

    let resp = app
        .router
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/xrpc/games.gamesgamesgamesgames.createGame")
                .header("content-type", "application/json")
                .body(Body::from(b"{}".to_vec()))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
#[serial]
async fn xrpc_post_non_procedure_returns_400() {
    let app = TestApp::new().await;
    seed_lexicons(&app).await;

    // Mock AIP userinfo so auth passes
    mock_aip_userinfo(&app.mock_server, "did:plc:test").await;

    let resp = app
        .router
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/xrpc/games.gamesgamesgamesgames.listGames")
                .header("authorization", "Bearer valid-token")
                .header("content-type", "application/json")
                .body(Body::from(b"{}".to_vec()))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
}
