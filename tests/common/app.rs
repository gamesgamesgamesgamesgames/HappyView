use axum::Router;
use happyview::config::Config;
use happyview::lexicon::LexiconRegistry;
use happyview::{AppState, admin, server};
use tokio::sync::watch;
use wiremock::MockServer;

use crate::common::db;

pub struct TestApp {
    pub router: Router,
    pub state: AppState,
    pub mock_server: MockServer,
    pub admin_secret: String,
}

impl TestApp {
    /// Build a fully wired TestApp with a real Postgres database and wiremock
    /// for external services (AIP, relay, PLC directory).
    pub async fn new() -> Self {
        let pool = db::test_pool().await;
        db::truncate_all(&pool).await;

        let mock_server = MockServer::start().await;
        let mock_url = mock_server.uri();

        let admin_secret = "test-admin-secret".to_string();

        let config = Config {
            host: "127.0.0.1".into(),
            port: 0,
            database_url: String::new(), // not used — pool is already connected
            aip_url: mock_url.clone(),
            jetstream_url: String::new(),
            admin_secret: Some(admin_secret.clone()),
            relay_url: mock_url.clone(),
            plc_url: mock_url.clone(),
        };

        admin::bootstrap(&pool, &config.admin_secret).await;

        let lexicons = LexiconRegistry::new();
        lexicons
            .load_from_db(&pool)
            .await
            .expect("failed to load lexicons");

        let initial_collections = lexicons.get_record_collections().await;
        let (collections_tx, _collections_rx) = watch::channel(initial_collections);

        let state = AppState {
            config,
            http: reqwest::Client::new(),
            db: pool,
            lexicons,
            collections_tx,
        };

        let router = server::router(state.clone());

        Self {
            router,
            state,
            mock_server,
            admin_secret,
        }
    }
}
