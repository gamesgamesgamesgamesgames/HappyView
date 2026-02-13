mod auth;
mod config;
mod error;
mod jetstream;
mod profile;
mod repo;
mod server;

use config::Config;
use tracing::info;

#[derive(Clone)]
pub struct AppState {
    pub config: Config,
    pub http: reqwest::Client,
    pub db: sqlx::PgPool,
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

    let state = AppState {
        config: config.clone(),
        http: reqwest::Client::new(),
        db,
    };

    jetstream::spawn(state.db.clone(), config.jetstream_url.clone());

    let app = server::router(state);
    let addr = config.listen_addr();

    info!(%addr, "HappyView is listening");

    let listener = tokio::net::TcpListener::bind(addr)
        .await
        .expect("failed to bind");

    axum::serve(listener, app).await.expect("server error");
}
