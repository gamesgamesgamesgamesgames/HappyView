pub mod admin;
pub mod aip;
pub mod auth;
pub mod config;
pub mod error;
pub mod event_log;
pub mod labeler;
pub mod lexicon;
pub mod lua;
pub mod profile;
pub mod rate_limit;
pub mod record_refs;
pub mod repo;
pub mod resolve;
pub mod server;
pub mod tap;
pub mod xrpc;

use config::Config;
use lexicon::LexiconRegistry;
use rate_limit::RateLimiter;
use std::sync::Arc;
use tokio::sync::watch;

#[derive(Clone)]
pub struct AppState {
    pub config: Config,
    pub http: reqwest::Client,
    pub db: sqlx::PgPool,
    pub lexicons: LexiconRegistry,
    pub collections_tx: watch::Sender<Vec<String>>,
    pub labeler_subscriptions_tx: watch::Sender<()>,
    pub rate_limiter: Arc<RateLimiter>,
}
