use happyview::config::Config;
use happyview::lexicon::{LexiconRegistry, ParsedLexicon};
use happyview::resolve::{fetch_lexicon_from_pds, resolve_nsid_authority};
use happyview::{AppState, backfill, jetstream, server};
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
    let network_rows: Vec<(String, String, Option<String>)> =
        sqlx::query_as("SELECT nsid, authority_did, target_collection FROM network_lexicons")
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
                        ) {
                            Ok(parsed) => {
                                // Upsert into lexicons table.
                                if let Err(e) = sqlx::query(
                                    r#"
                                    INSERT INTO lexicons (id, lexicon_json, backfill, target_collection)
                                    VALUES ($1, $2, false, $3)
                                    ON CONFLICT (id) DO UPDATE SET
                                        lexicon_json = EXCLUDED.lexicon_json,
                                        target_collection = EXCLUDED.target_collection,
                                        revision = lexicons.revision + 1,
                                        updated_at = NOW()
                                    "#,
                                )
                                .bind(nsid)
                                .bind(&lexicon_json)
                                .bind(target_collection)
                                .execute(&db)
                                .await
                                {
                                    warn!(nsid, "failed to upsert network lexicon into DB: {e}");
                                    continue;
                                }

                                // Update last_fetched_at.
                                let _ = sqlx::query(
                                    "UPDATE network_lexicons SET last_fetched_at = NOW() WHERE nsid = $1",
                                )
                                .bind(nsid)
                                .execute(&db)
                                .await;

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
    let (collections_tx, collections_rx) = watch::channel(initial_collections);

    let state = AppState {
        config: config.clone(),
        http,
        db,
        lexicons,
        collections_tx,
    };

    jetstream::spawn(
        state.db.clone(),
        config.jetstream_url.clone(),
        collections_rx,
        state.lexicons.clone(),
        state.collections_tx.clone(),
    );
    backfill::spawn_worker(
        state.db.clone(),
        state.http.clone(),
        config.relay_url.clone(),
        config.plc_url.clone(),
    );

    let app = server::router(state);
    let addr = config.listen_addr();

    info!(%addr, "HappyView is listening");

    let listener = tokio::net::TcpListener::bind(addr)
        .await
        .expect("failed to bind");

    axum::serve(listener, app).await.expect("server error");
}
