pub mod admin;
pub mod auth;
pub mod backfill;
pub mod config;
pub mod error;
pub mod jetstream;
pub mod lexicon;
pub mod profile;
pub mod repo;
pub mod resolve;
pub mod server;
pub mod xrpc;

use config::Config;
use lexicon::LexiconRegistry;
use tokio::sync::watch;

#[derive(Clone)]
pub struct AppState {
    pub config: Config,
    pub http: reqwest::Client,
    pub db: sqlx::PgPool,
    pub lexicons: LexiconRegistry,
    pub collections_tx: watch::Sender<Vec<String>>,
}
