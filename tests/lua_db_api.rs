mod common;

use happyview::AppState;
use happyview::config::Config;
use happyview::lexicon::LexiconRegistry;
use happyview::lua::db_api::register_db_api;
use mlua::Lua;
use serial_test::serial;
use std::sync::Arc;
use tokio::sync::watch;

use common::db;

/// Build an AppState backed by a real Postgres pool.
async fn test_state_with_pool(pool: sqlx::PgPool) -> AppState {
    let config = Config {
        host: "127.0.0.1".into(),
        port: 3000,
        database_url: String::new(),
        aip_url: String::new(),
        aip_public_url: String::new(),
        tap_url: String::new(),
        tap_admin_password: None,
        relay_url: String::new(),
        plc_url: String::new(),
        static_dir: String::new(),
        event_log_retention_days: 30,
    };
    let (tx, _) = watch::channel(vec![]);
    let (labeler_tx, _) = watch::channel(());
    AppState {
        config,
        http: reqwest::Client::new(),
        db: pool,
        lexicons: LexiconRegistry::new(),
        collections_tx: tx,
        labeler_subscriptions_tx: labeler_tx,
        rate_limiter: happyview::rate_limit::RateLimiter::new(
            false,
            happyview::rate_limit::RateLimitConfig {
                capacity: 100,
                refill_rate: 2.0,
                default_query_cost: 1,
                default_procedure_cost: 1,
                default_proxy_cost: 1,
            },
            vec![],
        ),
    }
}

/// Insert seed records for testing.
async fn seed_records(pool: &sqlx::PgPool) {
    let records = [
        (
            "at://did:plc:test/test.collection/rkey1",
            "did:plc:test",
            "test.collection",
            "rkey1",
            serde_json::json!({"name": "Test One", "value": 1}),
            "bafyone",
        ),
        (
            "at://did:plc:test/test.collection/rkey2",
            "did:plc:test",
            "test.collection",
            "rkey2",
            serde_json::json!({"name": "Test Two", "value": 2}),
            "bafytwo",
        ),
        (
            "at://did:plc:other/test.collection/rkey3",
            "did:plc:other",
            "test.collection",
            "rkey3",
            serde_json::json!({"name": "Other Record", "value": 3}),
            "bafythree",
        ),
    ];

    for (uri, did, collection, rkey, record, cid) in &records {
        sqlx::query(
            "INSERT INTO records (uri, did, collection, rkey, record, cid) VALUES ($1, $2, $3, $4, $5, $6)",
        )
        .bind(uri)
        .bind(did)
        .bind(collection)
        .bind(rkey)
        .bind(record)
        .bind(cid)
        .execute(pool)
        .await
        .expect("failed to seed record");
    }
}

fn setup_lua(state: &AppState) -> Lua {
    let lua = Lua::new();
    register_db_api(&lua, Arc::new(state.clone())).unwrap();
    lua
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[tokio::test]
#[serial]
async fn db_get_returns_record() {
    let pool = db::test_pool().await;
    db::truncate_all(&pool).await;
    seed_records(&pool).await;
    let state = test_state_with_pool(pool).await;
    let lua = setup_lua(&state);

    let result: mlua::Table = lua
        .load(r#"return db.get("at://did:plc:test/test.collection/rkey1")"#)
        .eval_async()
        .await
        .unwrap();

    assert_eq!(
        result.get::<String>("uri").unwrap(),
        "at://did:plc:test/test.collection/rkey1"
    );
    assert_eq!(result.get::<String>("name").unwrap(), "Test One");
}

#[tokio::test]
#[serial]
async fn db_get_returns_nil_for_missing() {
    let pool = db::test_pool().await;
    db::truncate_all(&pool).await;
    let state = test_state_with_pool(pool).await;
    let lua = setup_lua(&state);

    let result: mlua::Value = lua
        .load(r#"return db.get("at://did:plc:nonexistent/test.collection/nope")"#)
        .eval_async()
        .await
        .unwrap();

    assert!(result.is_nil());
}

#[tokio::test]
#[serial]
async fn db_query_returns_records() {
    let pool = db::test_pool().await;
    db::truncate_all(&pool).await;
    seed_records(&pool).await;
    let state = test_state_with_pool(pool).await;
    let lua = setup_lua(&state);

    let result: mlua::Table = lua
        .load(r#"return db.query({ collection = "test.collection" })"#)
        .eval_async()
        .await
        .unwrap();

    let records: mlua::Table = result.get("records").unwrap();
    assert_eq!(records.raw_len(), 3);
}

#[tokio::test]
#[serial]
async fn db_query_respects_limit() {
    let pool = db::test_pool().await;
    db::truncate_all(&pool).await;
    seed_records(&pool).await;
    let state = test_state_with_pool(pool).await;
    let lua = setup_lua(&state);

    let result: mlua::Table = lua
        .load(r#"return db.query({ collection = "test.collection", limit = 1 })"#)
        .eval_async()
        .await
        .unwrap();

    let records: mlua::Table = result.get("records").unwrap();
    assert_eq!(records.raw_len(), 1);

    // Should have a cursor since there are more records
    let cursor: String = result.get("cursor").unwrap();
    assert!(!cursor.is_empty());
}

#[tokio::test]
#[serial]
async fn db_count_returns_total() {
    let pool = db::test_pool().await;
    db::truncate_all(&pool).await;
    seed_records(&pool).await;
    let state = test_state_with_pool(pool).await;
    let lua = setup_lua(&state);

    let count: i64 = lua
        .load(r#"return db.count("test.collection")"#)
        .eval_async()
        .await
        .unwrap();

    assert_eq!(count, 3);
}

#[tokio::test]
#[serial]
async fn db_count_with_did_filter() {
    let pool = db::test_pool().await;
    db::truncate_all(&pool).await;
    seed_records(&pool).await;
    let state = test_state_with_pool(pool).await;
    let lua = setup_lua(&state);

    let count: i64 = lua
        .load(r#"return db.count("test.collection", "did:plc:test")"#)
        .eval_async()
        .await
        .unwrap();

    assert_eq!(count, 2);
}

#[tokio::test]
#[serial]
async fn db_search_finds_matching() {
    let pool = db::test_pool().await;
    db::truncate_all(&pool).await;
    seed_records(&pool).await;
    let state = test_state_with_pool(pool).await;
    let lua = setup_lua(&state);

    let result: mlua::Table = lua
        .load(
            r#"return db.search({ collection = "test.collection", field = "name", query = "Test" })"#,
        )
        .eval_async()
        .await
        .unwrap();

    let records: mlua::Table = result.get("records").unwrap();
    // "Test One" and "Test Two" match; "Other Record" does not
    assert_eq!(records.raw_len(), 2);
}

#[tokio::test]
#[serial]
async fn db_raw_select_works() {
    let pool = db::test_pool().await;
    db::truncate_all(&pool).await;
    seed_records(&pool).await;
    let state = test_state_with_pool(pool).await;
    let lua = setup_lua(&state);

    let result: mlua::Table = lua
        .load(
            r#"return db.raw("SELECT COUNT(*) as cnt FROM records WHERE collection = $1", {"test.collection"})"#,
        )
        .eval_async()
        .await
        .unwrap();

    // Result is an array of row tables
    let first_row: mlua::Table = result.get(1).unwrap();
    let cnt: i64 = first_row.get("cnt").unwrap();
    assert_eq!(cnt, 3);
}
