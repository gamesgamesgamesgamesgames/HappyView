use axum::Router;
use happyview::config::Config;
use happyview::lexicon::LexiconRegistry;
use happyview::{AppState, server};
use tokio::sync::watch;
use wiremock::MockServer;

use crate::common::db;

pub struct TestApp {
    pub router: Router,
    pub state: AppState,
    pub mock_server: MockServer,
    /// DID that is seeded as an admin in the test DB.
    pub admin_did: String,
    /// Bearer token used for admin requests (validated by the mocked AIP).
    pub admin_token: String,
}

impl TestApp {
    /// Build a fully wired TestApp with a real Postgres database and wiremock
    /// for external services (AIP, relay, PLC directory).
    pub async fn new() -> Self {
        let pool = db::test_pool().await;
        db::truncate_all(&pool).await;

        let mock_server = MockServer::start().await;
        let mock_url = mock_server.uri();

        let admin_did = "did:plc:testadmin".to_string();
        let admin_token = "test-admin-token".to_string();

        let config = Config {
            host: "127.0.0.1".into(),
            port: 0,
            database_url: String::new(), // not used — pool is already connected
            aip_url: mock_url.clone(),
            jetstream_url: String::new(),
            relay_url: mock_url.clone(),
            plc_url: mock_url.clone(),
        };

        // Seed the admin DID directly so tests don't rely on auto-bootstrap.
        sqlx::query("INSERT INTO admins (did) VALUES ($1) ON CONFLICT DO NOTHING")
            .bind(&admin_did)
            .execute(&pool)
            .await
            .expect("failed to seed admin DID");

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
            admin_did,
            admin_token,
        }
    }

    /// Mount the AIP userinfo mock that maps `self.admin_token` to
    /// `self.admin_did`. Call this before any admin request.
    pub async fn mock_admin_userinfo(&self) {
        use crate::common::auth::mock_aip_userinfo;
        mock_aip_userinfo(&self.mock_server, &self.admin_did).await;
    }
}
