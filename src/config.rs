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
}

impl Config {
    pub fn from_env() -> Self {
        Self {
            host: env::var("HOST").unwrap_or_else(|_| "0.0.0.0".into()),
            port: env::var("PORT")
                .ok()
                .and_then(|p| p.parse().ok())
                .unwrap_or(3000),
            database_url: env::var("DATABASE_URL")
                .expect("DATABASE_URL must be set"),
            aip_url: env::var("AIP_URL")
                .expect("AIP_URL must be set"),
            jetstream_url: env::var("JETSTREAM_URL")
                .unwrap_or_else(|_| "wss://jetstream2.us-west.bsky.network/subscribe".into()),
            admin_secret: env::var("ADMIN_SECRET").ok(),
            relay_url: env::var("RELAY_URL")
                .unwrap_or_else(|_| "https://bsky.network".into()),
        }
    }

    pub fn listen_addr(&self) -> SocketAddr {
        format!("{}:{}", self.host, self.port)
            .parse()
            .expect("invalid HOST/PORT")
    }
}
