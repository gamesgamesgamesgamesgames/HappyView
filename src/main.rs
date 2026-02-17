use happyview::config::Config;
use happyview::lexicon::{LexiconRegistry, ParsedLexicon, ProcedureAction};
use happyview::resolve::{fetch_lexicon_from_pds, resolve_nsid_authority};
use happyview::{AppState, server, tap};
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

    // Connect to Postgres.
    let db = sqlx::PgPool::connect(&config.database_url)
        .await
        .expect("failed to connect to database");

    info!("connected to database");

    sqlx::migrate!()
        .run(&db)
        .await
        .expect("failed to run migrations");

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
                        ) {
                            Ok(parsed) => {
                                if let Err(e) = sqlx::query(
                                    r#"
                                    UPDATE lexicons
                                    SET lexicon_json = $2,
                                        last_fetched_at = NOW(),
                                        revision = revision + 1,
                                        updated_at = NOW()
                                    WHERE id = $1 AND source = 'network'
                                    "#,
                                )
                                .bind(nsid)
                                .bind(&lexicon_json)
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

    let initial_collections = lexicons.get_record_collections().await;
    let initial_collections_for_sync = initial_collections.clone();
    let (collections_tx, collections_rx) = watch::channel(initial_collections);

    let state = AppState {
        config: config.clone(),
        http,
        db,
        lexicons,
        collections_tx,
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

    tap::spawn(
        state.db.clone(),
        config.tap_url.clone(),
        config.tap_admin_password.clone(),
        collections_rx,
        state.lexicons.clone(),
        state.collections_tx.clone(),
    );

    let app = server::router(state);
    let addr = config.listen_addr();

    info!(%addr, "HappyView is listening");

    let listener = tokio::net::TcpListener::bind(addr)
        .await
        .expect("failed to bind");

    axum::serve(listener, app).await.expect("server error");
}
