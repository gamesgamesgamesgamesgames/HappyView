use sha2::{Digest, Sha256};

use crate::db::{DatabaseBackend, adapt_sql};
use crate::error::AppError;

/// Resolved API client identity for DPoP operations.
pub struct ResolvedClient {
    pub id: String,
    pub client_key: String,
    pub client_type: String,
    pub scopes: String,
    pub allowed_origins: Option<Vec<String>>,
}

/// Authenticate a confidential client using client_key + client_secret.
pub async fn authenticate_confidential(
    pool: &sqlx::AnyPool,
    backend: DatabaseBackend,
    client_key: &str,
    client_secret: &str,
) -> Result<ResolvedClient, AppError> {
    let secret_hash = hex::encode(Sha256::digest(client_secret.as_bytes()));

    let sql = adapt_sql(
        "SELECT id, client_key, client_type, scopes, allowed_origins, client_secret_hash FROM api_clients WHERE client_key = ? AND is_active = 1",
        backend,
    );

    let row: Option<(String, String, String, String, Option<String>, String)> =
        sqlx::query_as(&sql)
            .bind(client_key)
            .fetch_optional(pool)
            .await
            .map_err(|e| AppError::Internal(format!("client lookup failed: {e}")))?;

    let (id, key, client_type, scopes, origins_json, stored_hash) =
        row.ok_or_else(|| AppError::Auth("invalid client credentials".into()))?;

    if stored_hash != secret_hash {
        return Err(AppError::Auth("invalid client credentials".into()));
    }

    if client_type != "confidential" {
        return Err(AppError::Auth(
            "this endpoint requires confidential client authentication".into(),
        ));
    }

    let allowed_origins =
        origins_json.map(|json| serde_json::from_str::<Vec<String>>(&json).unwrap_or_default());

    Ok(ResolvedClient {
        id,
        client_key: key,
        client_type,
        scopes,
        allowed_origins,
    })
}

/// Authenticate a public client using client_key + origin validation.
/// Returns the client but does NOT verify PKCE — that's done at session registration.
pub async fn authenticate_public(
    pool: &sqlx::AnyPool,
    backend: DatabaseBackend,
    client_key: &str,
    origin: Option<&str>,
) -> Result<ResolvedClient, AppError> {
    let sql = adapt_sql(
        "SELECT id, client_key, client_type, scopes, allowed_origins FROM api_clients WHERE client_key = ? AND is_active = 1",
        backend,
    );

    let row: Option<(String, String, String, String, Option<String>)> = sqlx::query_as(&sql)
        .bind(client_key)
        .fetch_optional(pool)
        .await
        .map_err(|e| AppError::Internal(format!("client lookup failed: {e}")))?;

    let (id, key, client_type, scopes, origins_json) =
        row.ok_or_else(|| AppError::Auth("unknown client".into()))?;

    if client_type != "public" {
        return Err(AppError::Auth(
            "this client is not registered as a public client".into(),
        ));
    }

    // Validate origin if the client has allowed_origins configured
    if let Some(ref origins_str) = origins_json {
        let allowed: Vec<String> = serde_json::from_str(origins_str).unwrap_or_default();
        if !allowed.is_empty() {
            match origin {
                Some(o) if allowed.iter().any(|a| a == o) => {}
                Some(o) => {
                    tracing::warn!(client_key, origin = o, "Origin mismatch for public client");
                    return Err(AppError::Auth("origin not allowed for this client".into()));
                }
                None => {
                    tracing::warn!(client_key, "No Origin header for public client");
                    return Err(AppError::Auth(
                        "Origin header required for public clients".into(),
                    ));
                }
            }
        }
    }

    let allowed_origins =
        origins_json.map(|json| serde_json::from_str::<Vec<String>>(&json).unwrap_or_default());

    Ok(ResolvedClient {
        id,
        client_key: key,
        client_type,
        scopes,
        allowed_origins,
    })
}

/// Resolve an API client by client_key only (no secret verification).
/// Used when the caller has already been authenticated by other means (e.g. DPoP proof).
pub async fn resolve_client_by_key(
    pool: &sqlx::AnyPool,
    backend: DatabaseBackend,
    client_key: &str,
) -> Result<ResolvedClient, AppError> {
    let sql = adapt_sql(
        "SELECT id, client_key, client_type, scopes, allowed_origins FROM api_clients WHERE client_key = ? AND is_active = 1",
        backend,
    );

    let row: Option<(String, String, String, String, Option<String>)> = sqlx::query_as(&sql)
        .bind(client_key)
        .fetch_optional(pool)
        .await
        .map_err(|e| AppError::Internal(format!("client lookup failed: {e}")))?;

    let (id, key, client_type, scopes, origins_json) =
        row.ok_or_else(|| AppError::Auth("unknown client".into()))?;

    let allowed_origins =
        origins_json.map(|json| serde_json::from_str::<Vec<String>>(&json).unwrap_or_default());

    Ok(ResolvedClient {
        id,
        client_key: key,
        client_type,
        scopes,
        allowed_origins,
    })
}

/// Validate that token scopes are allowed by the client's registered scopes.
///
/// Rules:
/// - `atproto` must be present in token scopes (always implicitly allowed)
/// - Every non-`atproto` scope in the token must appear in the client's registered scopes
pub fn validate_scopes(token_scopes: &str, client_scopes: &str) -> Result<(), AppError> {
    let token_set: std::collections::HashSet<&str> = token_scopes.split_whitespace().collect();
    let client_set: std::collections::HashSet<&str> = client_scopes.split_whitespace().collect();

    if !token_set.contains("atproto") {
        return Err(AppError::BadRequest(
            "token must include the 'atproto' scope".into(),
        ));
    }

    for scope in &token_set {
        if *scope == "atproto" {
            continue; // always allowed
        }
        if !client_set.contains(scope) {
            return Err(AppError::BadRequest(format!(
                "scope '{}' is not allowed for this client",
                scope
            )));
        }
    }

    Ok(())
}

/// Verify a PKCE challenge against a verifier.
pub fn verify_pkce(challenge: &str, verifier: &str) -> bool {
    use base64::Engine;
    use base64::engine::general_purpose::URL_SAFE_NO_PAD;
    let hash = Sha256::digest(verifier.as_bytes());
    let computed = URL_SAFE_NO_PAD.encode(hash);
    computed == challenge
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn validate_scopes_requires_atproto() {
        let result = validate_scopes("transition:generic", "atproto transition:generic");
        assert!(result.is_err());
    }

    #[test]
    fn validate_scopes_atproto_only_always_passes() {
        let result = validate_scopes("atproto", "com.example.whatever");
        assert!(result.is_ok());
    }

    #[test]
    fn validate_scopes_subset_passes() {
        let result = validate_scopes(
            "atproto com.example.basic",
            "atproto com.example.basic com.example.advanced",
        );
        assert!(result.is_ok());
    }

    #[test]
    fn validate_scopes_excess_scope_fails() {
        let result = validate_scopes(
            "atproto com.example.basic com.example.advanced",
            "atproto com.example.basic",
        );
        assert!(result.is_err());
    }

    #[test]
    fn validate_scopes_transition_generic_requires_registration() {
        let result = validate_scopes("atproto transition:generic", "atproto");
        assert!(result.is_err());

        let result = validate_scopes("atproto transition:generic", "atproto transition:generic");
        assert!(result.is_ok());
    }

    #[test]
    fn verify_pkce_valid() {
        use base64::Engine;
        use base64::engine::general_purpose::URL_SAFE_NO_PAD;

        let verifier = "test-verifier-string-12345678901234567890";
        let hash = sha2::Sha256::digest(verifier.as_bytes());
        let challenge = URL_SAFE_NO_PAD.encode(hash);

        assert!(verify_pkce(&challenge, verifier));
    }

    #[test]
    fn verify_pkce_invalid() {
        assert!(!verify_pkce("wrong-challenge", "some-verifier"));
    }
}
