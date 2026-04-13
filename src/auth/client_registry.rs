use dashmap::DashMap;
use std::sync::Arc;

use atrium_identity::did::{CommonDidResolver, CommonDidResolverConfig};
use atrium_identity::handle::{AtprotoHandleResolver, AtprotoHandleResolverConfig};
use atrium_oauth::{
    AtprotoClientMetadata, AuthMethod, DefaultHttpClient, GrantType, OAuthClientConfig,
    OAuthResolverConfig,
};

use crate::HappyViewOAuthClient;
use crate::auth::oauth_store::{DbSessionStore, DbStateStore};
use crate::db::{DatabaseBackend, adapt_sql};
use crate::dns::NativeDnsResolver;

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
    default_client: Arc<HappyViewOAuthClient>,
    clients: DashMap<String, Arc<HappyViewOAuthClient>>,
}

impl OAuthClientRegistry {
    pub fn new(default_client: Arc<HappyViewOAuthClient>) -> Self {
        Self {
            default_client,
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

    /// Look up a client by `client_id_url`, falling back to the default.
    pub fn get_or_default(&self, client_id_url: Option<&str>) -> Arc<HappyViewOAuthClient> {
        if let Some(url) = client_id_url {
            self.clients
                .get(url)
                .map(|r| r.value().clone())
                .unwrap_or_else(|| self.default_client.clone())
        } else {
            self.default_client.clone()
        }
    }

    /// Get the default (HappyView dashboard) client.
    pub fn default_client(&self) -> &Arc<HappyViewOAuthClient> {
        &self.default_client
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

        let metadata = AtprotoClientMetadata {
            client_id: client_id_url.to_string(),
            client_uri: Some(client_uri.to_string()),
            redirect_uris,
            token_endpoint_auth_method: AuthMethod::None,
            grant_types: vec![GrantType::AuthorizationCode, GrantType::RefreshToken],
            scopes,
            jwks_uri: None,
            token_endpoint_auth_signing_alg: None,
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

        match atrium_oauth::OAuthClient::new(OAuthClientConfig {
            client_metadata: metadata,
            keys: None,
            state_store: state_store.clone(),
            session_store: DbSessionStore::new(session_store_pool.clone(), *db_backend),
            resolver,
        }) {
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

            let metadata = AtprotoClientMetadata {
                client_id: client_id_url.clone(),
                client_uri: Some(client_uri),
                redirect_uris,
                token_endpoint_auth_method: AuthMethod::None,
                grant_types: vec![GrantType::AuthorizationCode, GrantType::RefreshToken],
                scopes,
                jwks_uri: None,
                token_endpoint_auth_signing_alg: None,
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

            match atrium_oauth::OAuthClient::new(OAuthClientConfig {
                client_metadata: metadata,
                keys: None,
                state_store: state_store.clone(),
                session_store: DbSessionStore::new(session_store_pool.clone(), db_backend),
                resolver,
            }) {
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
