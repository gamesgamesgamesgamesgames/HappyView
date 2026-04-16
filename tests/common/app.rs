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
        Self::new_with_registry_config(
            happyview::plugin::official_registry::RegistryConfig::production(),
        )
        .await
    }

    pub async fn new_with_registry_config(
        registry_config: happyview::plugin::official_registry::RegistryConfig,
    ) -> Self {
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
            jetstream_url: "wss://jetstream1.us-east.bsky.network".into(),
            relay_url: mock_url.clone(),
            plc_url: mock_url.clone(),
            static_dir: "./web/out".into(),
            event_log_retention_days: 30,
            app_name: None,
            logo_uri: None,
            tos_uri: None,
            policy_uri: None,
            token_encryption_key: None,
            default_rate_limit_capacity: 100,
            default_rate_limit_refill_rate: 2.0,
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
            db: pool.clone(),
            db_backend: backend,
            domain_cache: happyview::domain::DomainCache::new(),
            lexicons,
            collections_tx,
            labeler_subscriptions_tx,
            rate_limiter: happyview::rate_limit::RateLimiter::new(
                happyview::rate_limit::RateLimitDefaults {
                    query_cost: 1,
                    procedure_cost: 1,
                    proxy_cost: 1,
                },
            ),
            oauth: std::sync::Arc::new(happyview::auth::OAuthClientRegistry::new(
                std::sync::Arc::new(oauth),
            )),
            oauth_state_store: happyview::auth::oauth_store::DbStateStore::new(
                pool.clone(),
                backend,
            ),
            cookie_key: axum_extra::extract::cookie::Key::derive_from(
                b"test-secret-that-is-at-least-32-bytes-long",
            ),
            plugin_registry: std::sync::Arc::new(happyview::plugin::PluginRegistry::new()),
            wasm_runtime: std::sync::Arc::new(
                happyview::plugin::WasmRuntime::new().expect("wasm runtime"),
            ),
            attestation_signer: None,
            official_registry: std::sync::Arc::new(tokio::sync::RwLock::new(
                happyview::plugin::official_registry::OfficialRegistryState::default(),
            )),
            official_registry_config: registry_config,
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

    pub async fn new_with_encryption() -> Self {
        let mut app = Self::new().await;
        // Set a test encryption key (32 bytes)
        app.state.config.token_encryption_key = Some([0x42u8; 32]);
        // Rebuild the router with the updated state
        app.router = server::router(app.state.clone());
        app
    }

    /// Create an API client in the database for testing.
    /// Returns (client_key, client_secret, api_client_id).
    pub async fn create_api_client(
        &self,
        client_type: &str,
        allowed_origins: Option<Vec<String>>,
    ) -> (String, String, String) {
        use happyview::db::{adapt_sql, now_rfc3339};
        use rand::RngCore;
        use sha2::{Digest, Sha256};

        let mut key_bytes = [0u8; 16];
        rand::rng().fill_bytes(&mut key_bytes);
        let client_key = format!("hvc_{}", hex::encode(key_bytes));

        let mut secret_bytes = [0u8; 32];
        rand::rng().fill_bytes(&mut secret_bytes);
        let client_secret = format!("hvs_{}", hex::encode(secret_bytes));
        let secret_hash = hex::encode(Sha256::digest(client_secret.as_bytes()));

        let id = uuid::Uuid::new_v4().to_string();
        let now = now_rfc3339();
        let origins_json = allowed_origins
            .as_ref()
            .map(|o| serde_json::to_string(o).unwrap_or_else(|_| "[]".to_string()));

        let sql = adapt_sql(
            "INSERT INTO api_clients (id, client_key, client_secret_hash, name, client_id_url, client_uri, redirect_uris, scopes, client_type, allowed_origins, is_active, created_by, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 1, ?, ?, ?)",
            self.state.db_backend,
        );

        sqlx::query(&sql)
            .bind(&id)
            .bind(&client_key)
            .bind(&secret_hash)
            .bind("test-client")
            .bind(format!("https://test.example.com/oauth/{}", &id[..8]))
            .bind("https://test.example.com")
            .bind("[]")
            .bind("atproto")
            .bind(client_type)
            .bind(&origins_json)
            .bind(&self.admin_did)
            .bind(&now)
            .bind(&now)
            .execute(&self.state.db)
            .await
            .expect("failed to create test API client");

        (client_key, client_secret, id)
    }

    /// Build a Cookie header that authenticates as the admin user.
    pub fn admin_cookie(&self) -> (axum::http::HeaderName, axum::http::HeaderValue) {
        crate::common::auth::admin_cookie_header(&self.admin_did, &self.state.cookie_key)
    }

    /// Install a fake plugin directly into the registry at the given version.
    pub async fn install_fake_plugin(&self, id: &str, version: &str) {
        use happyview::plugin::{LoadedPlugin, PluginInfo, PluginSource};

        let plugin = LoadedPlugin {
            info: PluginInfo {
                id: id.to_string(),
                name: id.to_string(),
                version: version.to_string(),
                api_version: "1".to_string(),
                icon_url: None,
                required_secrets: vec![],
                auth_type: "openid".to_string(),
                config_schema: None,
            },
            source: PluginSource::Url {
                url: format!("https://example.com/{id}.wasm"),
                sha256: None,
            },
            wasm_bytes: vec![],
            manifest: None,
        };
        self.state.plugin_registry.register(plugin).await;
    }
}
