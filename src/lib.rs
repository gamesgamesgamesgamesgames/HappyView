pub mod admin;
pub mod auth;
pub mod config;
pub mod db;
pub mod dns;
pub mod error;
pub mod event_log;
pub mod external_auth;
pub mod labeler;
pub mod lexicon;
pub mod lua;
pub mod plugin;
pub mod profile;
pub mod rate_limit;
pub mod record_refs;
pub mod repo;
pub mod resolve;
pub mod server;
pub mod tap;
pub mod xrpc;

use auth::oauth_store::{DbSessionStore, DbStateStore};
use config::Config;
use db::DatabaseBackend;
use dns::NativeDnsResolver;
use lexicon::LexiconRegistry;
use rate_limit::RateLimiter;
use std::sync::Arc;
use tokio::sync::watch;

use atrium_identity::did::CommonDidResolver;
use atrium_identity::handle::AtprotoHandleResolver;
use atrium_oauth::DefaultHttpClient;

pub type HappyViewOAuthClient = atrium_oauth::OAuthClient<
    DbStateStore,
    DbSessionStore,
    CommonDidResolver<DefaultHttpClient>,
    AtprotoHandleResolver<NativeDnsResolver, DefaultHttpClient>,
>;

pub type HappyViewOAuthSession = atrium_oauth::OAuthSession<
    DefaultHttpClient,
    CommonDidResolver<DefaultHttpClient>,
    AtprotoHandleResolver<NativeDnsResolver, DefaultHttpClient>,
    DbSessionStore,
>;

#[derive(Clone)]
pub struct AppState {
    pub config: Config,
    pub http: reqwest::Client,
    pub db: sqlx::AnyPool,
    pub db_backend: DatabaseBackend,
    pub lexicons: LexiconRegistry,
    pub collections_tx: watch::Sender<Vec<String>>,
    pub labeler_subscriptions_tx: watch::Sender<()>,
    pub rate_limiter: Arc<RateLimiter>,
    pub oauth: Arc<HappyViewOAuthClient>,
    pub cookie_key: axum_extra::extract::cookie::Key,
    pub plugin_registry: Arc<plugin::PluginRegistry>,
    pub wasm_runtime: Arc<plugin::WasmRuntime>,
    pub attestation_signer: Option<Arc<plugin::attestation::AttestationSigner>>,
}

impl axum::extract::FromRef<AppState> for axum_extra::extract::cookie::Key {
    fn from_ref(state: &AppState) -> Self {
        state.cookie_key.clone()
    }
}
