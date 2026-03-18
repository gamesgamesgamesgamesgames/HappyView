mod common;

use atrium_identity::did::{CommonDidResolver, CommonDidResolverConfig};
use atrium_identity::handle::{AtprotoHandleResolver, AtprotoHandleResolverConfig};
use atrium_oauth::{
    AtprotoLocalhostClientMetadata, DefaultHttpClient, KnownScope, OAuthClientConfig,
    OAuthResolverConfig, Scope,
};
use happyview::AppState;
use happyview::config::Config;
use happyview::db::{DatabaseBackend, adapt_sql, now_rfc3339};
use happyview::lexicon::LexiconRegistry;
use serial_test::serial;
use tokio::sync::watch;

use common::db;

async fn test_state_with_pool(pool: sqlx::AnyPool, backend: DatabaseBackend) -> AppState {
    let config = Config {
        host: "127.0.0.1".into(),
        port: 3000,
        database_url: String::new(),
        database_backend: backend,
        public_url: String::new(),
        session_secret: "test-secret".into(),
        tap_url: String::new(),
        tap_admin_password: None,
        relay_url: String::new(),
        plc_url: String::new(),
        static_dir: String::new(),
        event_log_retention_days: 30,
    };
    let (tx, _) = watch::channel(vec![]);
    let (labeler_tx, _) = watch::channel(());
    let atrium_http = std::sync::Arc::new(DefaultHttpClient::default());
    let did_resolver = CommonDidResolver::new(CommonDidResolverConfig {
        plc_directory_url: "https://plc.directory".into(),
        http_client: std::sync::Arc::clone(&atrium_http),
    });
    let handle_resolver = AtprotoHandleResolver::new(AtprotoHandleResolverConfig {
        dns_txt_resolver: happyview::dns::NativeDnsResolver::new(),
        http_client: atrium_http,
    });
    let oauth_pool = db::test_pool().await;
    let oauth = atrium_oauth::OAuthClient::new(OAuthClientConfig {
        client_metadata: AtprotoLocalhostClientMetadata {
            redirect_uris: Some(vec!["http://127.0.0.1:0/auth/callback".into()]),
            scopes: Some(vec![Scope::Known(KnownScope::Atproto)]),
        },
        keys: None,
        state_store: happyview::auth::oauth_store::DbStateStore::new(oauth_pool.clone(), backend),
        session_store: happyview::auth::oauth_store::DbSessionStore::new(oauth_pool, backend),
        resolver: OAuthResolverConfig {
            did_resolver,
            handle_resolver,
            authorization_server_metadata: Default::default(),
            protected_resource_metadata: Default::default(),
        },
    })
    .expect("Failed to create test OAuth client");
    AppState {
        config,
        http: reqwest::Client::new(),
        db: pool,
        db_backend: backend,
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
        oauth: std::sync::Arc::new(oauth),
        cookie_key: axum_extra::extract::cookie::Key::derive_from(b"test-secret"),
    }
}

async fn seed_record(
    pool: &sqlx::AnyPool,
    backend: DatabaseBackend,
    uri: &str,
    did: &str,
    record: serde_json::Value,
) {
    let sql = adapt_sql(
        "INSERT INTO records (uri, did, collection, rkey, record, cid, created_at) VALUES (?, ?, ?, ?, ?, ?, ?)",
        backend,
    );
    sqlx::query(&sql)
        .bind(uri)
        .bind(did)
        .bind("test.collection")
        .bind("rkey1")
        .bind(serde_json::to_string(&record).unwrap_or_default())
        .bind("bafytest")
        .bind(now_rfc3339())
        .execute(pool)
        .await
        .expect("failed to seed record");
}

async fn seed_label(
    pool: &sqlx::AnyPool,
    backend: DatabaseBackend,
    src: &str,
    uri: &str,
    val: &str,
    exp: Option<&str>,
) {
    if let Some(exp) = exp {
        let sql = adapt_sql(
            "INSERT INTO labels (src, uri, val, cts, exp) VALUES (?, ?, ?, ?, ?)",
            backend,
        );
        sqlx::query(&sql)
            .bind(src)
            .bind(uri)
            .bind(val)
            .bind(now_rfc3339())
            .bind(exp)
            .execute(pool)
            .await
            .expect("failed to seed label");
    } else {
        let sql = adapt_sql(
            "INSERT INTO labels (src, uri, val, cts) VALUES (?, ?, ?, ?)",
            backend,
        );
        sqlx::query(&sql)
            .bind(src)
            .bind(uri)
            .bind(val)
            .bind(now_rfc3339())
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
#[ignore]
async fn get_labels_returns_external_labels() {
    let pool = db::test_pool().await;
    let backend = db::test_backend();
    db::truncate_all(&pool).await;

    let uri = "at://did:plc:test/test.collection/rkey1";
    seed_record(
        &pool,
        backend,
        uri,
        "did:plc:test",
        serde_json::json!({"name": "test"}),
    )
    .await;
    seed_label(
        &pool,
        backend,
        "did:plc:labeler1",
        uri,
        "adult-content",
        None,
    )
    .await;
    seed_label(&pool, backend, "did:plc:labeler1", uri, "violence", None).await;

    let state = test_state_with_pool(pool, backend).await;

    let now = now_rfc3339();
    let sql = adapt_sql(
        "SELECT src, uri, val FROM labels WHERE uri = ? AND (exp IS NULL OR exp > ?)",
        backend,
    );
    let rows: Vec<(String, String, String)> = sqlx::query_as(&sql)
        .bind(uri)
        .bind(&now)
        .fetch_all(&state.db)
        .await
        .unwrap();

    assert_eq!(rows.len(), 2);
    assert_eq!(rows[0].2, "adult-content");
    assert_eq!(rows[1].2, "violence");
}

#[tokio::test]
#[serial]
#[ignore]
async fn get_labels_filters_expired() {
    let pool = db::test_pool().await;
    let backend = db::test_backend();
    db::truncate_all(&pool).await;

    let uri = "at://did:plc:test/test.collection/rkey1";
    seed_record(
        &pool,
        backend,
        uri,
        "did:plc:test",
        serde_json::json!({"name": "test"}),
    )
    .await;

    // Active label
    seed_label(&pool, backend, "did:plc:labeler1", uri, "nudity", None).await;
    // Expired label (past date)
    seed_label(
        &pool,
        backend,
        "did:plc:labeler1",
        uri,
        "spam",
        Some("2020-01-01T00:00:00Z"),
    )
    .await;

    let state = test_state_with_pool(pool, backend).await;

    let now = now_rfc3339();
    let sql = adapt_sql(
        "SELECT src, uri, val FROM labels WHERE uri = ? AND (exp IS NULL OR exp > ?)",
        backend,
    );
    let rows: Vec<(String, String, String)> = sqlx::query_as(&sql)
        .bind(uri)
        .bind(&now)
        .fetch_all(&state.db)
        .await
        .unwrap();

    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0].2, "nudity");
}

#[tokio::test]
#[serial]
#[ignore]
async fn get_labels_includes_self_labels() {
    let pool = db::test_pool().await;
    let backend = db::test_backend();
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
    seed_record(&pool, backend, uri, "did:plc:author", record.clone()).await;

    let sql = adapt_sql("SELECT did, record FROM records WHERE uri = ?", backend);
    let fetched: Option<(String, String)> = sqlx::query_as(&sql)
        .bind(uri)
        .fetch_optional(&pool)
        .await
        .unwrap();

    let (did, rec_str) = fetched.unwrap();
    assert_eq!(did, "did:plc:author");

    let rec: serde_json::Value = serde_json::from_str(&rec_str).unwrap();
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
#[ignore]
async fn get_labels_empty_for_unlabeled_record() {
    let pool = db::test_pool().await;
    let backend = db::test_backend();
    db::truncate_all(&pool).await;

    let uri = "at://did:plc:test/test.collection/rkey1";
    seed_record(
        &pool,
        backend,
        uri,
        "did:plc:test",
        serde_json::json!({"name": "test"}),
    )
    .await;

    let now = now_rfc3339();
    let sql = adapt_sql(
        "SELECT src, uri, val FROM labels WHERE uri = ? AND (exp IS NULL OR exp > ?)",
        backend,
    );
    let rows: Vec<(String, String, String)> = sqlx::query_as(&sql)
        .bind(uri)
        .bind(&now)
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
#[ignore]
async fn get_labels_batch_returns_labels_per_uri() {
    let pool = db::test_pool().await;
    let backend = db::test_backend();
    db::truncate_all(&pool).await;

    let uri1 = "at://did:plc:test/test.collection/rkey1";
    let uri2 = "at://did:plc:test/test.collection/rkey2";

    seed_record(
        &pool,
        backend,
        uri1,
        "did:plc:test",
        serde_json::json!({"name": "one"}),
    )
    .await;

    let sql = adapt_sql(
        "INSERT INTO records (uri, did, collection, rkey, record, cid, created_at) VALUES (?, ?, ?, ?, ?, ?, ?)",
        backend,
    );
    sqlx::query(&sql)
        .bind(uri2)
        .bind("did:plc:test")
        .bind("test.collection")
        .bind("rkey2")
        .bind(serde_json::to_string(&serde_json::json!({"name": "two"})).unwrap_or_default())
        .bind("bafytest2")
        .bind(now_rfc3339())
        .execute(&pool)
        .await
        .unwrap();

    seed_label(&pool, backend, "did:plc:labeler1", uri1, "nudity", None).await;
    seed_label(&pool, backend, "did:plc:labeler1", uri2, "spam", None).await;
    seed_label(&pool, backend, "did:plc:labeler2", uri2, "violence", None).await;

    let now = now_rfc3339();
    let sql = adapt_sql(
        "SELECT src, uri, val FROM labels WHERE uri IN (?, ?) AND (exp IS NULL OR exp > ?)",
        backend,
    );
    let rows: Vec<(String, String, String)> = sqlx::query_as(&sql)
        .bind(uri1)
        .bind(uri2)
        .bind(&now)
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
#[ignore]
async fn get_labels_batch_empty_for_no_labels() {
    let pool = db::test_pool().await;
    let backend = db::test_backend();
    db::truncate_all(&pool).await;

    let uri1 = "at://did:plc:test/test.collection/rkey1";
    let uri2 = "at://did:plc:test/test.collection/rkey2";

    let now = now_rfc3339();
    let sql = adapt_sql(
        "SELECT src, uri, val FROM labels WHERE uri IN (?, ?) AND (exp IS NULL OR exp > ?)",
        backend,
    );
    let rows: Vec<(String, String, String)> = sqlx::query_as(&sql)
        .bind(uri1)
        .bind(uri2)
        .bind(&now)
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
#[ignore]
async fn label_negation_removes_row() {
    let pool = db::test_pool().await;
    let backend = db::test_backend();
    db::truncate_all(&pool).await;

    let uri = "at://did:plc:test/test.collection/rkey1";

    // Add a label
    seed_label(&pool, backend, "did:plc:labeler1", uri, "nudity", None).await;

    // Verify it exists
    let sql = adapt_sql(
        "SELECT COUNT(*) FROM labels WHERE src = ? AND uri = ? AND val = ?",
        backend,
    );
    let count: (i64,) = sqlx::query_as(&sql)
        .bind("did:plc:labeler1")
        .bind(uri)
        .bind("nudity")
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(count.0, 1);

    // Simulate negation (same logic as labeler.rs)
    let sql = adapt_sql(
        "DELETE FROM labels WHERE src = ? AND uri = ? AND val = ?",
        backend,
    );
    sqlx::query(&sql)
        .bind("did:plc:labeler1")
        .bind(uri)
        .bind("nudity")
        .execute(&pool)
        .await
        .unwrap();

    // Verify it's gone
    let sql = adapt_sql(
        "SELECT COUNT(*) FROM labels WHERE src = ? AND uri = ? AND val = ?",
        backend,
    );
    let count: (i64,) = sqlx::query_as(&sql)
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
#[ignore]
async fn label_upsert_is_idempotent() {
    let pool = db::test_pool().await;
    let backend = db::test_backend();
    db::truncate_all(&pool).await;

    let uri = "at://did:plc:test/test.collection/rkey1";

    let upsert_sql = match backend {
        DatabaseBackend::Postgres => {
            "INSERT INTO labels (src, uri, val, cts) VALUES ($1, $2, $3, $4) ON CONFLICT (src, uri, val) DO UPDATE SET cts = EXCLUDED.cts".to_string()
        }
        DatabaseBackend::Sqlite => {
            "INSERT INTO labels (src, uri, val, cts) VALUES (?, ?, ?, ?) ON CONFLICT (src, uri, val) DO UPDATE SET cts = excluded.cts".to_string()
        }
    };

    // Insert same label twice (upsert pattern from labeler.rs)
    for _ in 0..2 {
        sqlx::query(&upsert_sql)
            .bind("did:plc:labeler1")
            .bind(uri)
            .bind("nudity")
            .bind(now_rfc3339())
            .execute(&pool)
            .await
            .unwrap();
    }

    let sql = adapt_sql(
        "SELECT COUNT(*) FROM labels WHERE src = ? AND uri = ? AND val = ?",
        backend,
    );
    let count: (i64,) = sqlx::query_as(&sql)
        .bind("did:plc:labeler1")
        .bind(uri)
        .bind("nudity")
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(count.0, 1);
}
