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
            aip_url: mock_url.clone(),
            aip_public_url: mock_url.clone(),
            tap_url: "http://localhost:2480".into(),
            tap_admin_password: None,
            relay_url: mock_url.clone(),
            plc_url: mock_url.clone(),
            static_dir: "./web/out".into(),
            event_log_retention_days: 30,
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

    pub async fn mock_admin_userinfo(&self) {
        use crate::common::auth::mock_aip_userinfo;
        mock_aip_userinfo(&self.mock_server, &self.admin_did).await;
    }
}
