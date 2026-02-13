mod admin;
mod auth;
mod backfill;
mod config;
mod error;
mod jetstream;
mod lexicon;
mod profile;
mod repo;
mod server;
mod xrpc;

use config::Config;
use lexicon::LexiconRegistry;
use tokio::sync::watch;
use tracing::info;

#[derive(Clone)]
pub struct AppState {
    pub config: Config,
    pub http: reqwest::Client,
    pub db: sqlx::PgPool,
    pub lexicons: LexiconRegistry,
    pub collections_tx: watch::Sender<Vec<String>>,
}

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

    let initial_collections = lexicons.get_record_collections().await;
    let (collections_tx, collections_rx) = watch::channel(initial_collections);

    let state = AppState {
        config: config.clone(),
        http: reqwest::Client::new(),
        db,
        lexicons,
        collections_tx,
    };

    jetstream::spawn(state.db.clone(), config.jetstream_url.clone(), collections_rx);
    backfill::spawn_worker(state.db.clone(), state.http.clone(), config.relay_url.clone());

    let app = server::router(state);
    let addr = config.listen_addr();

    info!(%addr, "HappyView is listening");

    let listener = tokio::net::TcpListener::bind(addr)
        .await
        .expect("failed to bind");

    axum::serve(listener, app).await.expect("server error");
}
