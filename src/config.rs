use std::env;
use std::net::SocketAddr;

#[derive(Clone, Debug)]
pub struct Config {
    pub host: String,
    pub port: u16,
    pub database_url: String,
    pub aip_url: String,
    pub jetstream_url: String,
    pub admin_secret: Option<String>,
    pub relay_url: String,
    pub plc_url: String,
}

impl Config {
    pub fn from_env() -> Self {
        Self {
            host: env::var("HOST").unwrap_or_else(|_| "0.0.0.0".into()),
            port: env::var("PORT")
                .ok()
                .and_then(|p| p.parse().ok())
                .unwrap_or(3000),
            database_url: env::var("DATABASE_URL").expect("DATABASE_URL must be set"),
            aip_url: env::var("AIP_URL").expect("AIP_URL must be set"),
            jetstream_url: env::var("JETSTREAM_URL")
                .unwrap_or_else(|_| "wss://jetstream2.us-west.bsky.network/subscribe".into()),
            admin_secret: env::var("ADMIN_SECRET").ok(),
            relay_url: env::var("RELAY_URL").unwrap_or_else(|_| "https://bsky.network".into()),
            plc_url: env::var("PLC_URL").unwrap_or_else(|_| "https://plc.directory".into()),
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
            "AIP_URL",
            "JETSTREAM_URL",
            "ADMIN_SECRET",
            "RELAY_URL",
            "PLC_URL",
        ] {
            unsafe {
                env::remove_var(key);
            }
        }
    }

    unsafe fn set_required_env() {
        unsafe {
            env::set_var("DATABASE_URL", "postgres://localhost/test");
            env::set_var("AIP_URL", "http://localhost:4000");
        }
    }

    #[test]
    fn listen_addr_combines_host_and_port() {
        let config = Config {
            host: "127.0.0.1".into(),
            port: 8080,
            database_url: String::new(),
            aip_url: String::new(),
            jetstream_url: String::new(),
            admin_secret: None,
            relay_url: String::new(),
            plc_url: String::new(),
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
        assert_eq!(config.aip_url, "http://localhost:4000");
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
        assert!(config.jetstream_url.contains("jetstream"));
        assert_eq!(config.relay_url, "https://bsky.network");
        assert_eq!(config.plc_url, "https://plc.directory");
        assert!(config.admin_secret.is_none());
    }

    #[test]
    #[serial]
    fn from_env_reads_optional_overrides() {
        unsafe {
            clear_env();
            set_required_env();
            env::set_var("HOST", "10.0.0.1");
            env::set_var("PORT", "9090");
            env::set_var("ADMIN_SECRET", "s3cret");
            env::set_var("RELAY_URL", "https://relay.example.com");
            env::set_var("PLC_URL", "https://plc.example.com");
        }
        let config = Config::from_env();
        assert_eq!(config.host, "10.0.0.1");
        assert_eq!(config.port, 9090);
        assert_eq!(config.admin_secret, Some("s3cret".into()));
        assert_eq!(config.relay_url, "https://relay.example.com");
        assert_eq!(config.plc_url, "https://plc.example.com");
    }

    #[test]
    #[serial]
    #[should_panic(expected = "DATABASE_URL must be set")]
    fn from_env_panics_without_database_url() {
        unsafe {
            clear_env();
            env::set_var("AIP_URL", "http://localhost:4000");
        }
        Config::from_env();
    }

    #[test]
    #[serial]
    #[should_panic(expected = "AIP_URL must be set")]
    fn from_env_panics_without_aip_url() {
        unsafe {
            clear_env();
            env::set_var("DATABASE_URL", "postgres://localhost/test");
        }
        Config::from_env();
    }
}
