use atrium_identity::did::{CommonDidResolver, CommonDidResolverConfig};
use atrium_identity::handle::{AtprotoHandleResolver, AtprotoHandleResolverConfig};
use atrium_oauth::{
    AtprotoLocalhostClientMetadata, DefaultHttpClient, KnownScope, OAuthClientConfig,
    OAuthResolverConfig, Scope,
};
use axum::Router;
use happyview::config::Config;
use happyview::db::{DatabaseBackend, adapt_sql, now_rfc3339};
use happyview::lexicon::LexiconRegistry;
use happyview::{AppState, server};
use tokio::sync::watch;
use wiremock::MockServer;

use crate::common::db;

pub struct TestApp {
    pub router: Router,
    pub state: AppState,
    pub mock_server: MockServer,
    pub admin_did: String,
    pub admin_token: String,
}

impl TestApp {
    pub async fn new() -> Self {
        let pool = db::test_pool().await;
        let backend = db::test_backend();
        db::truncate_all(&pool).await;

        let mock_server = MockServer::start().await;
        let mock_url = mock_server.uri();

        let admin_did = "did:plc:testadmin".to_string();
        let admin_token = "test-admin-token".to_string();

        let config = Config {
            host: "127.0.0.1".into(),
            port: 0,
            database_url: String::new(),
            database_backend: backend,
            public_url: "http://127.0.0.1:0".into(),
            session_secret: "test-secret".into(),
            tap_url: "http://localhost:2480".into(),
            tap_admin_password: None,
            relay_url: mock_url.clone(),
            plc_url: mock_url.clone(),
            static_dir: "./web/out".into(),
            event_log_retention_days: 30,
            app_name: None,
            logo_uri: None,
            tos_uri: None,
            policy_uri: None,
            token_encryption_key: None,
        };

        let sql = adapt_sql(
            "INSERT INTO users (id, did, is_super, created_at) VALUES (?, ?, ?, ?) ON CONFLICT DO NOTHING",
            backend,
        );
        sqlx::query(&sql)
            .bind(uuid::Uuid::new_v4().to_string())
            .bind(&admin_did)
            .bind(1_i32)
            .bind(now_rfc3339())
            .execute(&pool)
            .await
            .expect("failed to seed admin user");

        let lexicons = LexiconRegistry::new();
        lexicons
            .load_from_db(&pool)
            .await
            .expect("failed to load lexicons");

        let initial_collections = lexicons.get_record_collections().await;
        let (collections_tx, _collections_rx) = watch::channel(initial_collections);
        let (labeler_subscriptions_tx, _) = watch::channel(());

        let atrium_http = std::sync::Arc::new(DefaultHttpClient::default());
        let did_resolver = CommonDidResolver::new(CommonDidResolverConfig {
            plc_directory_url: "https://plc.directory".into(),
            http_client: std::sync::Arc::clone(&atrium_http),
        });
        let handle_resolver = AtprotoHandleResolver::new(AtprotoHandleResolverConfig {
            dns_txt_resolver: happyview::dns::NativeDnsResolver::new(),
            http_client: atrium_http,
        });
        let oauth_pool = db::test_pool().await;
        let oauth = atrium_oauth::OAuthClient::new(OAuthClientConfig {
            client_metadata: AtprotoLocalhostClientMetadata {
                redirect_uris: Some(vec!["http://127.0.0.1:0/auth/callback".into()]),
                scopes: Some(vec![Scope::Known(KnownScope::Atproto)]),
            },
            keys: None,
            state_store: happyview::auth::oauth_store::DbStateStore::new(
                oauth_pool.clone(),
                backend,
            ),
            session_store: happyview::auth::oauth_store::DbSessionStore::new(oauth_pool, backend),
            resolver: OAuthResolverConfig {
                did_resolver,
                handle_resolver,
                authorization_server_metadata: Default::default(),
                protected_resource_metadata: Default::default(),
            },
        })
        .expect("Failed to create test OAuth client");

        let state = AppState {
            config,
            http: reqwest::Client::new(),
            db: pool,
            db_backend: backend,
            lexicons,
            collections_tx,
            labeler_subscriptions_tx,
            rate_limiter: happyview::rate_limit::RateLimiter::new(
                false,
                happyview::rate_limit::RateLimitConfig {
                    capacity: 100,
                    refill_rate: 2.0,
                    default_query_cost: 1,
                    default_procedure_cost: 1,
                    default_proxy_cost: 1,
                },
                vec![],
            ),
            oauth: std::sync::Arc::new(oauth),
            cookie_key: axum_extra::extract::cookie::Key::derive_from(
                b"test-secret-that-is-at-least-32-bytes-long",
            ),
            plugin_registry: std::sync::Arc::new(happyview::plugin::PluginRegistry::new()),
        };

        let router = server::router(state.clone());

        Self {
            router,
            state,
            mock_server,
            admin_did,
            admin_token,
        }
    }

    /// Build a Cookie header that authenticates as the admin user.
    pub fn admin_cookie(&self) -> (axum::http::HeaderName, axum::http::HeaderValue) {
        crate::common::auth::admin_cookie_header(&self.admin_did, &self.state.cookie_key)
    }
}
