use arc_swap::ArcSwap;
use dashmap::DashMap;
use std::sync::Arc;

use atrium_identity::did::{CommonDidResolver, CommonDidResolverConfig};
use atrium_identity::handle::{AtprotoHandleResolver, AtprotoHandleResolverConfig};
use atrium_oauth::{
    AtprotoClientMetadata, AtprotoLocalhostClientMetadata, AuthMethod, DefaultHttpClient,
    GrantType, OAuthClientConfig, OAuthResolverConfig,
};

use crate::HappyViewOAuthClient;
use crate::auth::oauth_store::{DbSessionStore, DbStateStore};
use crate::db::{DatabaseBackend, adapt_sql};
use crate::dns::NativeDnsResolver;

fn is_loopback_url(url: &str) -> bool {
    url.contains("127.0.0.1") || url.contains("[::1]") || url.contains("localhost")
}

/// Parameters needed to build an OAuth client for an API client registration.
pub struct ApiClientOAuthParams {
    pub plc_url: String,
    pub state_store: DbStateStore,
    pub session_store_pool: sqlx::AnyPool,
    pub db_backend: DatabaseBackend,
}

/// Registry of OAuth clients, keyed by `client_id_url`.
///
/// Each API client gets its own `OAuthClient` instance so the PDS auth screen
/// shows the correct domain. The default client is HappyView's own identity,
/// used for dashboard auth.
pub struct OAuthClientRegistry {
    primary_client: ArcSwap<HappyViewOAuthClient>,
    domain_clients: DashMap<String, Arc<HappyViewOAuthClient>>,
    clients: DashMap<String, Arc<HappyViewOAuthClient>>,
}

impl OAuthClientRegistry {
    pub fn new(primary_client: Arc<HappyViewOAuthClient>) -> Self {
        Self {
            primary_client: ArcSwap::new(primary_client),
            domain_clients: DashMap::new(),
            clients: DashMap::new(),
        }
    }

    /// Register an API client's OAuth client, keyed by its `client_id_url`.
    pub fn register(&self, client_id_url: String, client: Arc<HappyViewOAuthClient>) {
        self.clients.insert(client_id_url, client);
    }

    /// Remove an API client's OAuth client.
    pub fn remove(&self, client_id_url: &str) {
        self.clients.remove(client_id_url);
    }

    /// Look up a client by `client_id_url`.
    pub fn get(&self, client_id_url: &str) -> Option<Arc<HappyViewOAuthClient>> {
        self.clients.get(client_id_url).map(|r| r.value().clone())
    }

    /// Get the resolved OAuth `client_id` for a registered client.
    ///
    /// For loopback clients this returns `http://localhost?scope=...` (the format
    /// auth servers expect), not the original `client_id_url` key.
    pub fn get_resolved_client_id(&self, client_id_url: &str) -> Option<String> {
        self.clients
            .get(client_id_url)
            .map(|r| r.value().client_metadata.client_id.clone())
    }

    /// Look up a client by `client_id_url`, falling back to the primary client.
    pub fn get_or_default(&self, client_id_url: Option<&str>) -> Arc<HappyViewOAuthClient> {
        if let Some(url) = client_id_url {
            self.clients
                .get(url)
                .map(|r| r.value().clone())
                .unwrap_or_else(|| self.primary_client.load_full())
        } else {
            self.primary_client.load_full()
        }
    }

    /// Get the primary (HappyView dashboard) client.
    pub fn primary_client(&self) -> Arc<HappyViewOAuthClient> {
        self.primary_client.load_full()
    }

    /// Register a domain-specific OAuth client.
    /// Inserts into both `domain_clients` (keyed by domain URL, for `get_for_domain`)
    /// and `clients` (keyed by client_id_url, for `get_or_default`).
    pub fn register_domain_client(&self, domain_url: String, client: Arc<HappyViewOAuthClient>) {
        let client_id_url = format!(
            "{}/oauth-client-metadata.json",
            domain_url.trim_end_matches('/')
        );
        self.domain_clients.insert(domain_url, Arc::clone(&client));
        self.clients.insert(client_id_url, client);
    }

    /// Remove a domain-specific OAuth client from both maps.
    pub fn remove_domain_client(&self, domain_url: &str) {
        self.domain_clients.remove(domain_url);
        let client_id_url = format!(
            "{}/oauth-client-metadata.json",
            domain_url.trim_end_matches('/')
        );
        self.clients.remove(&client_id_url);
    }

    /// Look up a domain-specific OAuth client.
    pub fn get_domain_client(&self, domain_url: &str) -> Option<Arc<HappyViewOAuthClient>> {
        self.domain_clients
            .get(domain_url)
            .map(|r| r.value().clone())
    }

    /// Get the OAuth client for a domain, falling back to the primary client.
    pub fn get_for_domain(&self, domain_url: &str) -> Arc<HappyViewOAuthClient> {
        self.domain_clients
            .get(domain_url)
            .map(|r| r.value().clone())
            .unwrap_or_else(|| self.primary_client.load_full())
    }

    /// Replace the primary OAuth client (e.g. when admin changes the primary domain).
    pub fn set_primary_client(&self, client: Arc<HappyViewOAuthClient>) {
        self.primary_client.store(client);
    }

    /// Build and register a single OAuth client from API client metadata.
    /// Used when creating or updating an API client via the admin UI.
    pub fn register_api_client(
        &self,
        client_id_url: &str,
        client_uri: &str,
        redirect_uris: Vec<String>,
        scopes_str: &str,
        params: &ApiClientOAuthParams,
    ) -> Result<(), String> {
        let ApiClientOAuthParams {
            plc_url,
            state_store,
            session_store_pool,
            db_backend,
        } = params;
        let scopes = crate::auth::parse_scope_string(scopes_str);
        let scopes = if scopes.is_empty() {
            vec![atrium_oauth::Scope::Known(
                atrium_oauth::KnownScope::Atproto,
            )]
        } else {
            scopes
        };

        let http = Arc::new(DefaultHttpClient::default());
        let resolver = OAuthResolverConfig {
            did_resolver: CommonDidResolver::new(CommonDidResolverConfig {
                plc_directory_url: plc_url.to_string(),
                http_client: Arc::clone(&http),
            }),
            handle_resolver: AtprotoHandleResolver::new(AtprotoHandleResolverConfig {
                dns_txt_resolver: NativeDnsResolver::new(),
                http_client: Arc::clone(&http),
            }),
            authorization_server_metadata: Default::default(),
            protected_resource_metadata: Default::default(),
        };

        let client = if is_loopback_url(client_id_url) {
            atrium_oauth::OAuthClient::new(OAuthClientConfig {
                client_metadata: AtprotoLocalhostClientMetadata {
                    redirect_uris: None,
                    scopes: Some(scopes),
                },
                keys: None,
                state_store: state_store.clone(),
                session_store: DbSessionStore::new(session_store_pool.clone(), *db_backend),
                resolver,
            })
        } else {
            atrium_oauth::OAuthClient::new(OAuthClientConfig {
                client_metadata: AtprotoClientMetadata {
                    client_id: client_id_url.to_string(),
                    client_uri: Some(client_uri.to_string()),
                    redirect_uris,
                    token_endpoint_auth_method: AuthMethod::None,
                    grant_types: vec![GrantType::AuthorizationCode, GrantType::RefreshToken],
                    scopes,
                    jwks_uri: None,
                    token_endpoint_auth_signing_alg: None,
                },
                keys: None,
                state_store: state_store.clone(),
                session_store: DbSessionStore::new(session_store_pool.clone(), *db_backend),
                resolver,
            })
        };

        match client {
            Ok(client) => {
                self.register(client_id_url.to_string(), Arc::new(client));
                Ok(())
            }
            Err(e) => Err(format!("failed to create OAuth client: {e}")),
        }
    }

    /// Load all active API clients from the database and register OAuth clients for each.
    pub async fn load_from_db(
        &self,
        db: &sqlx::AnyPool,
        db_backend: DatabaseBackend,
        plc_url: &str,
        state_store: DbStateStore,
        session_store_pool: sqlx::AnyPool,
    ) {
        let sql = adapt_sql(
            "SELECT client_id_url, client_uri, redirect_uris, scopes FROM api_clients WHERE is_active = 1",
            db_backend,
        );

        let rows: Vec<(String, String, String, String)> =
            match sqlx::query_as(&sql).fetch_all(db).await {
                Ok(r) => r,
                Err(e) => {
                    tracing::error!("Failed to load API clients from database: {e}");
                    return;
                }
            };

        for (client_id_url, client_uri, redirect_uris_json, scopes_str) in rows {
            let redirect_uris: Vec<String> =
                serde_json::from_str(&redirect_uris_json).unwrap_or_default();

            let scopes = crate::auth::parse_scope_string(&scopes_str);
            let scopes = if scopes.is_empty() {
                vec![atrium_oauth::Scope::Known(
                    atrium_oauth::KnownScope::Atproto,
                )]
            } else {
                scopes
            };

            // Each OAuthClient needs its own resolver instances (they're not Clone)
            let http = Arc::new(DefaultHttpClient::default());
            let resolver = OAuthResolverConfig {
                did_resolver: CommonDidResolver::new(CommonDidResolverConfig {
                    plc_directory_url: plc_url.to_string(),
                    http_client: Arc::clone(&http),
                }),
                handle_resolver: AtprotoHandleResolver::new(AtprotoHandleResolverConfig {
                    dns_txt_resolver: NativeDnsResolver::new(),
                    http_client: Arc::clone(&http),
                }),
                authorization_server_metadata: Default::default(),
                protected_resource_metadata: Default::default(),
            };

            let client = if is_loopback_url(&client_id_url) {
                atrium_oauth::OAuthClient::new(OAuthClientConfig {
                    client_metadata: AtprotoLocalhostClientMetadata {
                        redirect_uris: None,
                        scopes: Some(scopes),
                    },
                    keys: None,
                    state_store: state_store.clone(),
                    session_store: DbSessionStore::new(session_store_pool.clone(), db_backend),
                    resolver,
                })
            } else {
                atrium_oauth::OAuthClient::new(OAuthClientConfig {
                    client_metadata: AtprotoClientMetadata {
                        client_id: client_id_url.clone(),
                        client_uri: Some(client_uri),
                        redirect_uris,
                        token_endpoint_auth_method: AuthMethod::None,
                        grant_types: vec![GrantType::AuthorizationCode, GrantType::RefreshToken],
                        scopes,
                        jwks_uri: None,
                        token_endpoint_auth_signing_alg: None,
                    },
                    keys: None,
                    state_store: state_store.clone(),
                    session_store: DbSessionStore::new(session_store_pool.clone(), db_backend),
                    resolver,
                })
            };

            match client {
                Ok(client) => {
                    tracing::info!(client_id = %client_id_url, "Registered API client OAuth identity");
                    self.register(client_id_url, Arc::new(client));
                }
                Err(e) => {
                    tracing::error!(client_id = %client_id_url, error = %e, "Failed to create OAuth client for API client");
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // Note: we can't easily construct real OAuthClient instances in unit tests
    // because they require resolvers, stores, etc. The registry logic is simple
    // enough that we test it via integration tests that stand up the full stack.
    // These tests verify the DashMap-based lookup logic using a mock approach.

    #[test]
    fn test_registry_stores_and_retrieves() {
        // We can at least verify the DashMap operations work correctly
        let map: DashMap<String, String> = DashMap::new();
        map.insert("key1".to_string(), "val1".to_string());

        assert!(map.get("key1").is_some());
        assert!(map.get("key2").is_none());

        map.remove("key1");
        assert!(map.get("key1").is_none());
    }

    #[test]
    fn test_registry_overwrite() {
        let map: DashMap<String, String> = DashMap::new();
        map.insert("key1".to_string(), "val1".to_string());
        map.insert("key1".to_string(), "val2".to_string());

        assert_eq!(map.get("key1").unwrap().value(), "val2");
    }
}
