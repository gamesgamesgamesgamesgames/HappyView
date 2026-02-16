pub mod admin;
pub mod aip;
pub mod auth;
pub mod config;
pub mod error;
pub mod lexicon;
pub mod profile;
pub mod repo;
pub mod resolve;
pub mod server;
pub mod tap;
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
