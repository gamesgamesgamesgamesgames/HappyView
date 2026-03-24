use std::env;
use std::net::SocketAddr;

use crate::db::DatabaseBackend;

#[derive(Clone, Debug)]
pub struct Config {
    pub host: String,
    pub port: u16,
    pub database_url: String,
    pub database_backend: DatabaseBackend,
    pub public_url: String,
    pub session_secret: String,
    pub jetstream_url: String,
    pub relay_url: String,
    pub plc_url: String,
    pub static_dir: String,
    pub event_log_retention_days: u32,
    pub app_name: Option<String>,
    pub logo_uri: Option<String>,
    pub tos_uri: Option<String>,
    pub policy_uri: Option<String>,
    pub token_encryption_key: Option<[u8; 32]>,
}

impl Config {
    pub fn from_env() -> Self {
        let database_url = env::var("DATABASE_URL").expect("DATABASE_URL must be set");
        let database_backend = env::var("DATABASE_BACKEND")
            .ok()
            .and_then(|s| DatabaseBackend::from_str(&s))
            .unwrap_or_else(|| DatabaseBackend::from_url(&database_url));

        Self {
            host: env::var("HOST").unwrap_or_else(|_| "0.0.0.0".into()),
            port: env::var("PORT")
                .ok()
                .and_then(|p| p.parse().ok())
                .unwrap_or(3000),
            database_url,
            database_backend,
            public_url: env::var("PUBLIC_URL").expect("PUBLIC_URL must be set"),
            session_secret: env::var("SESSION_SECRET")
                .unwrap_or_else(|_| "change-me-in-production-not-secure".into()),
            jetstream_url: env::var("JETSTREAM_URL")
                .unwrap_or_else(|_| "wss://jetstream1.us-east.bsky.network".into()),
            relay_url: env::var("RELAY_URL").unwrap_or_else(|_| "https://bsky.network".into()),
            plc_url: env::var("PLC_URL").unwrap_or_else(|_| "https://plc.directory".into()),
            static_dir: env::var("STATIC_DIR").unwrap_or_else(|_| "./web/out".into()),
            event_log_retention_days: std::env::var("EVENT_LOG_RETENTION_DAYS")
                .ok()
                .and_then(|v| v.parse().ok())
                .unwrap_or(30),
            app_name: env::var("APP_NAME").ok(),
            logo_uri: env::var("LOGO_URI").ok(),
            tos_uri: env::var("TOS_URI").ok(),
            policy_uri: env::var("POLICY_URI").ok(),
            token_encryption_key: env::var("TOKEN_ENCRYPTION_KEY").ok().and_then(|s| {
                use base64::Engine;
                base64::engine::general_purpose::STANDARD
                    .decode(&s)
                    .ok()
                    .and_then(|bytes| bytes.try_into().ok())
            }),
        }
    }

    pub fn listen_addr(&self) -> SocketAddr {
        format!("{}:{}", self.host, self.port)
            .parse()
            .expect("invalid HOST/PORT")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serial_test::serial;

    unsafe fn clear_env() {
        for key in [
            "HOST",
            "PORT",
            "DATABASE_URL",
            "DATABASE_BACKEND",
            "PUBLIC_URL",
            "SESSION_SECRET",
            "JETSTREAM_URL",
            "RELAY_URL",
            "PLC_URL",
            "EVENT_LOG_RETENTION_DAYS",
            "APP_NAME",
            "LOGO_URI",
            "TOS_URI",
            "POLICY_URI",
        ] {
            unsafe {
                env::remove_var(key);
            }
        }
    }

    unsafe fn set_required_env() {
        unsafe {
            env::set_var("DATABASE_URL", "postgres://localhost/test");
            env::set_var("PUBLIC_URL", "http://127.0.0.1:3000");
        }
    }

    #[test]
    fn listen_addr_combines_host_and_port() {
        let config = Config {
            host: "127.0.0.1".into(),
            port: 8080,
            database_url: String::new(),
            database_backend: DatabaseBackend::Postgres,
            public_url: String::new(),
            session_secret: String::new(),
            jetstream_url: String::new(),
            relay_url: String::new(),
            plc_url: String::new(),
            static_dir: String::new(),
            event_log_retention_days: 30,
            app_name: None,
            logo_uri: None,
            tos_uri: None,
            policy_uri: None,
            token_encryption_key: None,
        };
        assert_eq!(
            config.listen_addr(),
            "127.0.0.1:8080".parse::<SocketAddr>().unwrap()
        );
    }

    #[test]
    #[serial]
    fn from_env_reads_required_vars() {
        unsafe {
            clear_env();
            set_required_env();
        }
        let config = Config::from_env();
        assert_eq!(config.database_url, "postgres://localhost/test");
        assert_eq!(config.public_url, "http://127.0.0.1:3000");
    }

    #[test]
    #[serial]
    fn from_env_applies_defaults() {
        unsafe {
            clear_env();
            set_required_env();
        }
        let config = Config::from_env();
        assert_eq!(config.host, "0.0.0.0");
        assert_eq!(config.port, 3000);
        assert_eq!(
            config.jetstream_url,
            "wss://jetstream1.us-east.bsky.network"
        );
        assert_eq!(config.relay_url, "https://bsky.network");
        assert_eq!(config.plc_url, "https://plc.directory");
    }

    #[test]
    #[serial]
    fn from_env_reads_optional_overrides() {
        unsafe {
            clear_env();
            set_required_env();
            env::set_var("HOST", "10.0.0.1");
            env::set_var("PORT", "9090");
            env::set_var("RELAY_URL", "https://relay.example.com");
            env::set_var("PLC_URL", "https://plc.example.com");
        }
        let config = Config::from_env();
        assert_eq!(config.host, "10.0.0.1");
        assert_eq!(config.port, 9090);
        assert_eq!(config.relay_url, "https://relay.example.com");
        assert_eq!(config.plc_url, "https://plc.example.com");
    }

    #[test]
    #[serial]
    #[should_panic(expected = "DATABASE_URL must be set")]
    fn from_env_panics_without_database_url() {
        unsafe {
            clear_env();
            env::set_var("PUBLIC_URL", "http://127.0.0.1:3000");
        }
        Config::from_env();
    }

    #[test]
    #[serial]
    #[should_panic(expected = "PUBLIC_URL must be set")]
    fn from_env_panics_without_public_url() {
        unsafe {
            clear_env();
            env::set_var("DATABASE_URL", "postgres://localhost/test");
        }
        Config::from_env();
    }

    #[test]
    #[serial]
    fn default_event_log_retention_days() {
        unsafe {
            clear_env();
            set_required_env();
        }
        let config = Config::from_env();
        assert_eq!(config.event_log_retention_days, 30);
    }

    #[test]
    #[serial]
    fn custom_event_log_retention_days() {
        unsafe {
            clear_env();
            set_required_env();
            env::set_var("EVENT_LOG_RETENTION_DAYS", "7");
        }
        let config = Config::from_env();
        assert_eq!(config.event_log_retention_days, 7);
    }

    #[test]
    #[serial]
    fn zero_event_log_retention_days_disables_cleanup() {
        unsafe {
            clear_env();
            set_required_env();
            env::set_var("EVENT_LOG_RETENTION_DAYS", "0");
        }
        let config = Config::from_env();
        assert_eq!(config.event_log_retention_days, 0);
    }

    #[test]
    #[serial]
    fn database_backend_detected_from_url() {
        unsafe {
            clear_env();
            env::set_var("DATABASE_URL", "postgres://localhost/test");
            env::set_var("PUBLIC_URL", "http://127.0.0.1:3000");
        }
        let config = Config::from_env();
        assert_eq!(config.database_backend, DatabaseBackend::Postgres);
    }

    #[test]
    #[serial]
    fn database_backend_sqlite_detected_from_url() {
        unsafe {
            clear_env();
            env::set_var("DATABASE_URL", "sqlite://data/happyview.db?mode=rwc");
            env::set_var("PUBLIC_URL", "http://127.0.0.1:3000");
        }
        let config = Config::from_env();
        assert_eq!(config.database_backend, DatabaseBackend::Sqlite);
    }

    #[test]
    #[serial]
    fn database_backend_override_from_env() {
        unsafe {
            clear_env();
            env::set_var("DATABASE_URL", "postgres://localhost/test");
            env::set_var("DATABASE_BACKEND", "sqlite");
            env::set_var("PUBLIC_URL", "http://127.0.0.1:3000");
        }
        let config = Config::from_env();
        assert_eq!(config.database_backend, DatabaseBackend::Sqlite);
    }
}
