use happyview::config::Config;
use happyview::db;
use happyview::lexicon::{LexiconRegistry, ParsedLexicon, ProcedureAction};
use happyview::rate_limit::RateLimiter;
use happyview::resolve::{fetch_lexicon_from_pds, resolve_nsid_authority};
use happyview::{AppState, labeler, server, tap};
use tokio::sync::watch;
use tracing::{info, warn};

#[tokio::main]
async fn main() {
    dotenvy::dotenv().ok();

    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "happyview=debug,tower_http=debug".parse().unwrap()),
        )
        .init();

    let config = Config::from_env();
    let db_backend = config.database_backend;

    // Connect to database and run migrations.
    let db = db::connect(&config.database_url, db_backend).await;

    info!(
        backend = ?db_backend,
        "connected to database"
    );

    // Backfill record_refs in the background (first run after upgrade)
    {
        let db_bg = db.clone();
        let backend = db_backend;
        tokio::spawn(async move {
            let count: (i64,) = sqlx::query_as("SELECT COUNT(*) FROM record_refs")
                .fetch_one(&db_bg)
                .await
                .expect("failed to count record_refs");

            if count.0 == 0 {
                info!("backfilling record_refs table in background...");
                let total: (i64,) = sqlx::query_as("SELECT COUNT(*) FROM records")
                    .fetch_one(&db_bg)
                    .await
                    .expect("failed to count records");
                let total = total.0 as usize;

                let batch_size = 1000i64;
                let mut offset = 0i64;
                let mut processed = 0usize;

                let query = db::adapt_sql(
                    "SELECT uri, collection, record FROM records ORDER BY uri LIMIT ? OFFSET ?",
                    backend,
                );

                loop {
                    let batch: Vec<(String, String, String)> = sqlx::query_as(&query)
                        .bind(batch_size)
                        .bind(offset)
                        .fetch_all(&db_bg)
                        .await
                        .expect("failed to fetch records for backfill");

                    if batch.is_empty() {
                        break;
                    }

                    for (uri, collection, record_str) in &batch {
                        let record: serde_json::Value =
                            serde_json::from_str(record_str).unwrap_or(serde_json::Value::Null);
                        if let Err(e) = happyview::record_refs::sync_refs(
                            &db_bg, uri, collection, &record, backend,
                        )
                        .await
                        {
                            warn!(uri = uri.as_str(), "failed to backfill refs: {e}");
                        }
                    }

                    processed += batch.len();
                    offset += batch_size;

                    if processed.is_multiple_of(10000) || processed == total {
                        info!("backfill progress: {processed}/{total}");
                    }
                }

                info!("backfill complete: processed {processed} records");
            }
        });
    }

    let lexicons = LexiconRegistry::new();
    lexicons
        .load_from_db(&db)
        .await
        .expect("failed to load lexicons");

    // Re-fetch all network lexicons from their respective PDSes.
    let http = reqwest::Client::new();
    let network_rows: Vec<(String, Option<String>, Option<String>)> = sqlx::query_as(
        "SELECT id, authority_did, target_collection FROM lexicons WHERE source = 'network'",
    )
    .fetch_all(&db)
    .await
    .unwrap_or_default();

    for (nsid, _authority_did, target_collection) in &network_rows {
        match resolve_nsid_authority(&http, &config.plc_url, nsid).await {
            Ok((did, pds_endpoint)) => {
                match fetch_lexicon_from_pds(&http, &pds_endpoint, &did, nsid).await {
                    Ok(lexicon_json) => {
                        match ParsedLexicon::parse(
                            lexicon_json.clone(),
                            1,
                            target_collection.clone(),
                            ProcedureAction::Upsert,
                            None,
                            None,
                            None,
                        ) {
                            Ok(parsed) => {
                                let now = db::now_rfc3339();
                                let update_sql = db::adapt_sql(
                                    "UPDATE lexicons SET lexicon_json = ?, last_fetched_at = ?, revision = revision + 1, updated_at = ? WHERE id = ? AND source = 'network'",
                                    db_backend,
                                );
                                let lexicon_json_str =
                                    serde_json::to_string(&lexicon_json).unwrap_or_default();
                                if let Err(e) = sqlx::query(&update_sql)
                                    .bind(&lexicon_json_str)
                                    .bind(&now)
                                    .bind(&now)
                                    .bind(nsid)
                                    .execute(&db)
                                    .await
                                {
                                    warn!(nsid, "failed to update network lexicon in DB: {e}");
                                    continue;
                                }

                                lexicons.upsert(parsed).await;
                                info!(nsid, "refreshed network lexicon");
                            }
                            Err(e) => warn!(nsid, "failed to parse network lexicon: {e}"),
                        }
                    }
                    Err(e) => warn!(nsid, "failed to fetch network lexicon from PDS: {e}"),
                }
            }
            Err(e) => warn!(nsid, "failed to resolve network lexicon authority: {e}"),
        }
    }

    if !network_rows.is_empty() {
        info!(
            count = network_rows.len(),
            "processed network lexicons on startup"
        );
    }

    // Initialize rate limiter from DB.
    let rl_state = RateLimiter::load_from_db(&db).await;
    let rate_limiter = RateLimiter::new(rl_state.enabled, rl_state.global, rl_state.allowlist);
    tokio::spawn(rate_limiter.clone().spawn_cleanup());

    let initial_collections = lexicons.get_record_collections().await;
    let initial_collections_for_sync = initial_collections.clone();
    let (collections_tx, collections_rx) = watch::channel(initial_collections);
    let (labeler_subscriptions_tx, labeler_subscriptions_rx) = watch::channel(());

    let state = AppState {
        config: config.clone(),
        http,
        db,
        db_backend,
        lexicons,
        collections_tx,
        labeler_subscriptions_tx,
        rate_limiter,
    };

    // Sync initial collections to Tap on startup.
    {
        let mut wanted = initial_collections_for_sync;
        if !wanted.contains(&"com.atproto.lexicon.schema".to_string()) {
            wanted.push("com.atproto.lexicon.schema".to_string());
        }
        if let Err(e) = tap::sync_collections(
            &state.http,
            &config.tap_url,
            config.tap_admin_password.as_deref(),
            &wanted,
        )
        .await
        {
            warn!("failed to sync initial collections to tap: {e}");
        }
    }

    tap::spawn(state.clone(), collections_rx);

    labeler::spawn(state.clone(), labeler_subscriptions_rx);
    tokio::spawn(labeler::spawn_label_gc(state.db.clone(), state.db_backend));

    tokio::spawn(happyview::event_log::spawn_retention_cleanup(
        state.db.clone(),
        state.config.event_log_retention_days,
        state.db_backend,
    ));

    let app = server::router(state);
    let addr = config.listen_addr();

    info!(%addr, "HappyView is listening");

    let listener = tokio::net::TcpListener::bind(addr)
        .await
        .expect("failed to bind");

    axum::serve(listener, app).await.expect("server error");
}
