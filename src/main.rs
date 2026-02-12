mod auth;
mod config;
mod error;
mod server;

use std::time::Duration;

use config::Config;
use tracing::info;

use crate::auth::jwks::JwksProvider;

#[derive(Clone)]
pub struct AppState {
    pub config: Config,
    pub jwks: JwksProvider,
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

    // Set up JWKS provider pointed at AIP.
    let jwks = JwksProvider::new(config.jwks_url());
    if let Err(e) = jwks.refresh().await {
        tracing::warn!("initial JWKS fetch failed (AIP may not be running yet): {e}");
    }
    jwks.clone().spawn_refresh_loop(Duration::from_secs(300));

    let state = AppState {
        config: config.clone(),
        jwks,
        db,
    };

    let app = server::router(state);
    let addr = config.listen_addr();

    info!(%addr, "HappyView is listening");

    let listener = tokio::net::TcpListener::bind(addr)
        .await
        .expect("failed to bind");

    axum::serve(listener, app).await.expect("server error");
}
