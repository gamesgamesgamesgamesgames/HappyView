mod common;

use happyview::AppState;
use happyview::config::Config;
use happyview::lexicon::LexiconRegistry;
use serial_test::serial;
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

/// Seed a record into the records table.
async fn seed_record(pool: &sqlx::PgPool, uri: &str, did: &str, record: serde_json::Value) {
    sqlx::query(
        "INSERT INTO records (uri, did, collection, rkey, record, cid) VALUES ($1, $2, $3, $4, $5, $6)",
    )
    .bind(uri)
    .bind(did)
    .bind("test.collection")
    .bind("rkey1")
    .bind(record)
    .bind("bafytest")
    .execute(pool)
    .await
    .expect("failed to seed record");
}

/// Seed a label into the labels table.
async fn seed_label(pool: &sqlx::PgPool, src: &str, uri: &str, val: &str, exp: Option<&str>) {
    if let Some(exp) = exp {
        sqlx::query(
            "INSERT INTO labels (src, uri, val, cts, exp) VALUES ($1, $2, $3, NOW(), $4::timestamptz)",
        )
        .bind(src)
        .bind(uri)
        .bind(val)
        .bind(exp)
        .execute(pool)
        .await
        .expect("failed to seed label");
    } else {
        sqlx::query("INSERT INTO labels (src, uri, val, cts) VALUES ($1, $2, $3, NOW())")
            .bind(src)
            .bind(uri)
            .bind(val)
            .execute(pool)
            .await
            .expect("failed to seed label");
    }
}

// ---------------------------------------------------------------------------
// get_labels tests
// ---------------------------------------------------------------------------

#[tokio::test]
#[serial]
async fn get_labels_returns_external_labels() {
    let pool = db::test_pool().await;
    db::truncate_all(&pool).await;

    let uri = "at://did:plc:test/test.collection/rkey1";
    seed_record(
        &pool,
        uri,
        "did:plc:test",
        serde_json::json!({"name": "test"}),
    )
    .await;
    seed_label(&pool, "did:plc:labeler1", uri, "adult-content", None).await;
    seed_label(&pool, "did:plc:labeler1", uri, "violence", None).await;

    let state = test_state_with_pool(pool).await;

    // atproto_api is pub(crate) so we test the underlying queries directly.
    let rows: Vec<(String, String, String)> = sqlx::query_as(
        "SELECT src, uri, val FROM labels WHERE uri = $1 AND (exp IS NULL OR exp > NOW())",
    )
    .bind(uri)
    .fetch_all(&state.db)
    .await
    .unwrap();

    assert_eq!(rows.len(), 2);
    assert_eq!(rows[0].2, "adult-content");
    assert_eq!(rows[1].2, "violence");
}

#[tokio::test]
#[serial]
async fn get_labels_filters_expired() {
    let pool = db::test_pool().await;
    db::truncate_all(&pool).await;

    let uri = "at://did:plc:test/test.collection/rkey1";
    seed_record(
        &pool,
        uri,
        "did:plc:test",
        serde_json::json!({"name": "test"}),
    )
    .await;

    // Active label
    seed_label(&pool, "did:plc:labeler1", uri, "nudity", None).await;
    // Expired label (past date)
    seed_label(
        &pool,
        "did:plc:labeler1",
        uri,
        "spam",
        Some("2020-01-01T00:00:00Z"),
    )
    .await;

    let state = test_state_with_pool(pool).await;

    // Query with expiry filter (same as get_labels does internally)
    let rows: Vec<(String, String, String)> = sqlx::query_as(
        "SELECT src, uri, val FROM labels WHERE uri = $1 AND (exp IS NULL OR exp > NOW())",
    )
    .bind(uri)
    .fetch_all(&state.db)
    .await
    .unwrap();

    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0].2, "nudity");
}

#[tokio::test]
#[serial]
async fn get_labels_includes_self_labels() {
    let pool = db::test_pool().await;
    db::truncate_all(&pool).await;

    let uri = "at://did:plc:author/test.collection/rkey1";
    let record = serde_json::json!({
        "name": "test",
        "labels": {
            "values": [
                { "val": "sexual" },
                { "val": "graphic-media" }
            ]
        }
    });
    seed_record(&pool, uri, "did:plc:author", record.clone()).await;

    // Verify self-labels can be extracted from record JSON
    let fetched: Option<(String, serde_json::Value)> =
        sqlx::query_as("SELECT did, record FROM records WHERE uri = $1")
            .bind(uri)
            .fetch_optional(&pool)
            .await
            .unwrap();

    let (did, rec) = fetched.unwrap();
    assert_eq!(did, "did:plc:author");

    let self_labels: Vec<&str> = rec
        .get("labels")
        .and_then(|l| l.get("values"))
        .and_then(|v| v.as_array())
        .unwrap()
        .iter()
        .filter_map(|item| item.get("val").and_then(|v| v.as_str()))
        .collect();

    assert_eq!(self_labels, vec!["sexual", "graphic-media"]);
}

#[tokio::test]
#[serial]
async fn get_labels_empty_for_unlabeled_record() {
    let pool = db::test_pool().await;
    db::truncate_all(&pool).await;

    let uri = "at://did:plc:test/test.collection/rkey1";
    seed_record(
        &pool,
        uri,
        "did:plc:test",
        serde_json::json!({"name": "test"}),
    )
    .await;

    let rows: Vec<(String, String, String)> = sqlx::query_as(
        "SELECT src, uri, val FROM labels WHERE uri = $1 AND (exp IS NULL OR exp > NOW())",
    )
    .bind(uri)
    .fetch_all(&pool)
    .await
    .unwrap();

    assert!(rows.is_empty());
}

// ---------------------------------------------------------------------------
// get_labels_batch tests
// ---------------------------------------------------------------------------

#[tokio::test]
#[serial]
async fn get_labels_batch_returns_labels_per_uri() {
    let pool = db::test_pool().await;
    db::truncate_all(&pool).await;

    let uri1 = "at://did:plc:test/test.collection/rkey1";
    let uri2 = "at://did:plc:test/test.collection/rkey2";

    seed_record(
        &pool,
        uri1,
        "did:plc:test",
        serde_json::json!({"name": "one"}),
    )
    .await;

    // Use different rkey for second record to avoid PK conflict
    sqlx::query(
        "INSERT INTO records (uri, did, collection, rkey, record, cid) VALUES ($1, $2, $3, $4, $5, $6)",
    )
    .bind(uri2)
    .bind("did:plc:test")
    .bind("test.collection")
    .bind("rkey2")
    .bind(serde_json::json!({"name": "two"}))
    .bind("bafytest2")
    .execute(&pool)
    .await
    .unwrap();

    seed_label(&pool, "did:plc:labeler1", uri1, "nudity", None).await;
    seed_label(&pool, "did:plc:labeler1", uri2, "spam", None).await;
    seed_label(&pool, "did:plc:labeler2", uri2, "violence", None).await;

    let uris = vec![uri1.to_string(), uri2.to_string()];

    // Batch query (same as get_labels_batch does internally)
    let rows: Vec<(String, String, String)> = sqlx::query_as(
        "SELECT src, uri, val FROM labels WHERE uri = ANY($1) AND (exp IS NULL OR exp > NOW())",
    )
    .bind(&uris)
    .fetch_all(&pool)
    .await
    .unwrap();

    // uri1 has 1 label, uri2 has 2 labels
    let uri1_labels: Vec<_> = rows.iter().filter(|r| r.1 == uri1).collect();
    let uri2_labels: Vec<_> = rows.iter().filter(|r| r.1 == uri2).collect();

    assert_eq!(uri1_labels.len(), 1);
    assert_eq!(uri1_labels[0].2, "nudity");
    assert_eq!(uri2_labels.len(), 2);
}

#[tokio::test]
#[serial]
async fn get_labels_batch_empty_for_no_labels() {
    let pool = db::test_pool().await;
    db::truncate_all(&pool).await;

    let uris = vec![
        "at://did:plc:test/test.collection/rkey1".to_string(),
        "at://did:plc:test/test.collection/rkey2".to_string(),
    ];

    let rows: Vec<(String, String, String)> = sqlx::query_as(
        "SELECT src, uri, val FROM labels WHERE uri = ANY($1) AND (exp IS NULL OR exp > NOW())",
    )
    .bind(&uris)
    .fetch_all(&pool)
    .await
    .unwrap();

    assert!(rows.is_empty());
}

// ---------------------------------------------------------------------------
// Label negation (materialized state)
// ---------------------------------------------------------------------------

#[tokio::test]
#[serial]
async fn label_negation_removes_row() {
    let pool = db::test_pool().await;
    db::truncate_all(&pool).await;

    let uri = "at://did:plc:test/test.collection/rkey1";

    // Add a label
    seed_label(&pool, "did:plc:labeler1", uri, "nudity", None).await;

    // Verify it exists
    let count: (i64,) =
        sqlx::query_as("SELECT COUNT(*) FROM labels WHERE src = $1 AND uri = $2 AND val = $3")
            .bind("did:plc:labeler1")
            .bind(uri)
            .bind("nudity")
            .fetch_one(&pool)
            .await
            .unwrap();
    assert_eq!(count.0, 1);

    // Simulate negation (same logic as labeler.rs)
    sqlx::query("DELETE FROM labels WHERE src = $1 AND uri = $2 AND val = $3")
        .bind("did:plc:labeler1")
        .bind(uri)
        .bind("nudity")
        .execute(&pool)
        .await
        .unwrap();

    // Verify it's gone
    let count: (i64,) =
        sqlx::query_as("SELECT COUNT(*) FROM labels WHERE src = $1 AND uri = $2 AND val = $3")
            .bind("did:plc:labeler1")
            .bind(uri)
            .bind("nudity")
            .fetch_one(&pool)
            .await
            .unwrap();
    assert_eq!(count.0, 0);
}

// ---------------------------------------------------------------------------
// Label upsert (idempotent)
// ---------------------------------------------------------------------------

#[tokio::test]
#[serial]
async fn label_upsert_is_idempotent() {
    let pool = db::test_pool().await;
    db::truncate_all(&pool).await;

    let uri = "at://did:plc:test/test.collection/rkey1";

    // Insert same label twice (upsert pattern from labeler.rs)
    for _ in 0..2 {
        sqlx::query(
            "INSERT INTO labels (src, uri, val, cts) VALUES ($1, $2, $3, NOW()) ON CONFLICT (src, uri, val) DO UPDATE SET cts = EXCLUDED.cts",
        )
        .bind("did:plc:labeler1")
        .bind(uri)
        .bind("nudity")
        .execute(&pool)
        .await
        .unwrap();
    }

    let count: (i64,) =
        sqlx::query_as("SELECT COUNT(*) FROM labels WHERE src = $1 AND uri = $2 AND val = $3")
            .bind("did:plc:labeler1")
            .bind(uri)
            .bind("nudity")
            .fetch_one(&pool)
            .await
            .unwrap();
    assert_eq!(count.0, 1);
}
