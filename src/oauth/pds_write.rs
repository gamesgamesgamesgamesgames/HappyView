use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use p256::ecdsa::{SigningKey, signature::Signer};
use sha2::{Digest, Sha256};

use std::sync::Arc;

use crate::auth::OAuthClientRegistry;
use crate::db::DatabaseBackend;
use crate::error::AppError;
use crate::plugin::encryption::decrypt;

use super::sessions::DpopSession;

/// Resolved DPoP credentials needed to make authenticated PDS requests.
struct DpopCredentials {
    session: DpopSession,
    pds_url: String,
    private_jwk: serde_json::Value,
}

/// Resolve DPoP credentials: session, PDS URL, and decrypted private key.
async fn resolve_credentials(
    http: &reqwest::Client,
    pool: &sqlx::AnyPool,
    backend: DatabaseBackend,
    encryption_key: &[u8; 32],
    plc_url: &str,
    api_client_id: &str,
    user_did: &str,
) -> Result<DpopCredentials, AppError> {
    let session =
        super::sessions::get_dpop_session(pool, backend, encryption_key, api_client_id, user_did)
            .await?;

    let pds_url = match session.pds_url {
        Some(ref url) => url.clone(),
        None => resolve_pds_from_did(http, plc_url, user_did).await?,
    };

    let key_sql = crate::db::adapt_sql(
        "SELECT private_key_enc FROM dpop_keys WHERE id = ?",
        backend,
    );
    let row: Option<(Vec<u8>,)> = sqlx::query_as(&key_sql)
        .bind(&session.dpop_key_id)
        .fetch_optional(pool)
        .await
        .map_err(|e| AppError::Internal(format!("failed to look up DPoP key: {e}")))?;

    let (encrypted_key,) = row.ok_or_else(|| AppError::Internal("DPoP key not found".into()))?;

    let key_bytes = decrypt(encryption_key, &encrypted_key)
        .map_err(|e| AppError::Internal(format!("failed to decrypt DPoP key: {e}")))?;

    let private_jwk: serde_json::Value = serde_json::from_slice(&key_bytes)
        .map_err(|e| AppError::Internal(format!("failed to parse DPoP key: {e}")))?;

    Ok(DpopCredentials {
        session,
        pds_url,
        private_jwk,
    })
}

/// Make an authenticated POST, handling DPoP nonce negotiation and token refresh.
#[allow(clippy::too_many_arguments)]
async fn dpop_post_with_retry(
    http: &reqwest::Client,
    pool: &sqlx::AnyPool,
    backend: DatabaseBackend,
    encryption_key: &[u8; 32],
    oauth_registry: &Arc<OAuthClientRegistry>,
    creds: &mut DpopCredentials,
    target_url: &str,
    request_builder: impl Fn(&reqwest::Client, &str, &str) -> reqwest::RequestBuilder,
) -> Result<reqwest::Response, AppError> {
    let proof = generate_dpop_proof(
        &creds.private_jwk,
        "POST",
        target_url,
        &creds.session.access_token,
        None,
    )?;

    let resp = request_builder(http, &creds.session.access_token, &proof)
        .send()
        .await
        .map_err(|e| AppError::Internal(format!("PDS request failed: {e}")))?;

    // Handle DPoP nonce requirement
    if let Some(nonce) = extract_dpop_nonce(&resp) {
        let proof = generate_dpop_proof(
            &creds.private_jwk,
            "POST",
            target_url,
            &creds.session.access_token,
            Some(&nonce),
        )?;

        let resp = request_builder(http, &creds.session.access_token, &proof)
            .send()
            .await
            .map_err(|e| AppError::Internal(format!("PDS request failed: {e}")))?;

        // If we still get invalid_token after nonce, try refresh
        if is_expired_token(&resp) {
            return retry_after_refresh(
                http,
                pool,
                backend,
                encryption_key,
                oauth_registry,
                creds,
                target_url,
                Some(&nonce),
                &request_builder,
            )
            .await;
        }

        return Ok(resp);
    }

    // Handle expired token
    if is_expired_token(&resp) {
        return retry_after_refresh(
            http,
            pool,
            backend,
            encryption_key,
            oauth_registry,
            creds,
            target_url,
            None,
            &request_builder,
        )
        .await;
    }

    Ok(resp)
}

/// Refresh the access token and retry the PDS request.
#[allow(clippy::too_many_arguments)]
async fn retry_after_refresh(
    http: &reqwest::Client,
    pool: &sqlx::AnyPool,
    backend: DatabaseBackend,
    encryption_key: &[u8; 32],
    oauth_registry: &Arc<OAuthClientRegistry>,
    creds: &mut DpopCredentials,
    target_url: &str,
    nonce: Option<&str>,
    request_builder: &impl Fn(&reqwest::Client, &str, &str) -> reqwest::RequestBuilder,
) -> Result<reqwest::Response, AppError> {
    refresh_access_token(http, pool, backend, encryption_key, oauth_registry, creds).await?;

    let proof = generate_dpop_proof(
        &creds.private_jwk,
        "POST",
        target_url,
        &creds.session.access_token,
        nonce,
    )?;

    let resp = request_builder(http, &creds.session.access_token, &proof)
        .send()
        .await
        .map_err(|e| AppError::Internal(format!("PDS request failed after token refresh: {e}")))?;

    // One more nonce negotiation attempt after refresh
    if let Some(new_nonce) = extract_dpop_nonce(&resp) {
        let proof = generate_dpop_proof(
            &creds.private_jwk,
            "POST",
            target_url,
            &creds.session.access_token,
            Some(&new_nonce),
        )?;

        let resp = request_builder(http, &creds.session.access_token, &proof)
            .send()
            .await
            .map_err(|e| AppError::Internal(format!("PDS request failed: {e}")))?;

        return Ok(resp);
    }

    Ok(resp)
}

/// Make an authenticated POST to a PDS XRPC endpoint using a DPoP session.
#[allow(clippy::too_many_arguments)]
pub async fn dpop_pds_post(
    http: &reqwest::Client,
    pool: &sqlx::AnyPool,
    backend: DatabaseBackend,
    encryption_key: &[u8; 32],
    oauth_registry: &Arc<OAuthClientRegistry>,
    plc_url: &str,
    api_client_id: &str,
    user_did: &str,
    xrpc_method: &str,
    body: &serde_json::Value,
) -> Result<reqwest::Response, AppError> {
    let mut creds = resolve_credentials(
        http,
        pool,
        backend,
        encryption_key,
        plc_url,
        api_client_id,
        user_did,
    )
    .await?;

    let target_url = format!(
        "{}/xrpc/{}",
        creds.pds_url.trim_end_matches('/'),
        xrpc_method
    );

    let body = body.clone();
    let target = target_url.clone();
    dpop_post_with_retry(
        http,
        pool,
        backend,
        encryption_key,
        oauth_registry,
        &mut creds,
        &target_url,
        |http, access_token, proof| {
            http.post(&target)
                .header("Authorization", format!("DPoP {access_token}"))
                .header("DPoP", proof)
                .header("Content-Type", "application/json")
                .json(&body)
        },
    )
    .await
}

/// Make an authenticated blob upload to a PDS using a DPoP session.
#[allow(clippy::too_many_arguments)]
pub async fn dpop_pds_post_blob(
    http: &reqwest::Client,
    pool: &sqlx::AnyPool,
    backend: DatabaseBackend,
    encryption_key: &[u8; 32],
    oauth_registry: &Arc<OAuthClientRegistry>,
    plc_url: &str,
    api_client_id: &str,
    user_did: &str,
    content_type: &str,
    blob: bytes::Bytes,
) -> Result<reqwest::Response, AppError> {
    let mut creds = resolve_credentials(
        http,
        pool,
        backend,
        encryption_key,
        plc_url,
        api_client_id,
        user_did,
    )
    .await?;

    let target_url = format!(
        "{}/xrpc/com.atproto.repo.uploadBlob",
        creds.pds_url.trim_end_matches('/')
    );

    let content_type = content_type.to_string();
    let target = target_url.clone();
    dpop_post_with_retry(
        http,
        pool,
        backend,
        encryption_key,
        oauth_registry,
        &mut creds,
        &target_url,
        |http, access_token, proof| {
            http.post(&target)
                .header("Authorization", format!("DPoP {access_token}"))
                .header("DPoP", proof)
                .header("Content-Type", &content_type)
                .body(blob.clone())
        },
    )
    .await
}

/// Check if a response is a 401 with an expired/invalid token error.
fn is_expired_token(resp: &reqwest::Response) -> bool {
    resp.status() == reqwest::StatusCode::UNAUTHORIZED
}

/// Check if a response indicates that a DPoP nonce is required, and extract it.
fn extract_dpop_nonce(resp: &reqwest::Response) -> Option<String> {
    if resp.status() == reqwest::StatusCode::UNAUTHORIZED
        || resp.status() == reqwest::StatusCode::BAD_REQUEST
    {
        resp.headers()
            .get("dpop-nonce")
            .and_then(|v| v.to_str().ok())
            .map(|s| s.to_string())
    } else {
        None
    }
}

/// Refresh an expired access token using the session's refresh_token.
///
/// Discovers the token endpoint from the issuer's OAuth metadata, sends a
/// `grant_type=refresh_token` request with a DPoP proof, and updates the
/// stored session with the new tokens.
async fn refresh_access_token(
    http: &reqwest::Client,
    pool: &sqlx::AnyPool,
    backend: DatabaseBackend,
    encryption_key: &[u8; 32],
    oauth_registry: &Arc<OAuthClientRegistry>,
    creds: &mut DpopCredentials,
) -> Result<(), AppError> {
    let refresh_token = creds
        .session
        .refresh_token
        .as_deref()
        .ok_or_else(|| AppError::Auth("token expired and no refresh_token available".into()))?;

    let issuer = creds
        .session
        .issuer
        .as_deref()
        .ok_or_else(|| AppError::Auth("token expired and no issuer URL stored".into()))?;

    let token_endpoint = discover_token_endpoint(http, issuer).await?;

    // Get the resolved client_id from the OAuth registry. For loopback clients
    // this returns `http://localhost?scope=...` which auth servers handle inline,
    // rather than the `client_id_url` from the DB which they'd try to fetch.
    let client_id_url = lookup_client_id_url(pool, backend, &creds.session.api_client_id).await?;
    let client_id = oauth_registry
        .get_resolved_client_id(&client_id_url)
        .unwrap_or(client_id_url);

    let proof = generate_dpop_proof_no_ath(&creds.private_jwk, "POST", &token_endpoint, None)?;

    let resp = http
        .post(&token_endpoint)
        .header("DPoP", &proof)
        .header("Content-Type", "application/x-www-form-urlencoded")
        .form(&[
            ("grant_type", "refresh_token"),
            ("refresh_token", refresh_token),
            ("client_id", &client_id),
        ])
        .send()
        .await
        .map_err(|e| AppError::Internal(format!("token refresh request failed: {e}")))?;

    // Handle nonce requirement on the token endpoint
    if let Some(nonce) = extract_dpop_nonce(&resp) {
        let proof =
            generate_dpop_proof_no_ath(&creds.private_jwk, "POST", &token_endpoint, Some(&nonce))?;

        let resp = http
            .post(&token_endpoint)
            .header("DPoP", &proof)
            .header("Content-Type", "application/x-www-form-urlencoded")
            .form(&[
                ("grant_type", "refresh_token"),
                ("refresh_token", refresh_token),
                ("client_id", &client_id),
            ])
            .send()
            .await
            .map_err(|e| AppError::Internal(format!("token refresh request failed: {e}")))?;

        return handle_refresh_response(http, pool, backend, encryption_key, creds, resp).await;
    }

    handle_refresh_response(http, pool, backend, encryption_key, creds, resp).await
}

/// Parse the token refresh response and update the stored session.
async fn handle_refresh_response(
    _http: &reqwest::Client,
    pool: &sqlx::AnyPool,
    backend: DatabaseBackend,
    encryption_key: &[u8; 32],
    creds: &mut DpopCredentials,
    resp: reqwest::Response,
) -> Result<(), AppError> {
    if !resp.status().is_success() {
        let status = resp.status();
        let body = resp.text().await.unwrap_or_default();
        return Err(AppError::Auth(format!(
            "token refresh failed ({status}): {body}"
        )));
    }

    let token_resp: serde_json::Value = resp
        .json()
        .await
        .map_err(|e| AppError::Internal(format!("invalid token refresh response: {e}")))?;

    let new_access_token = token_resp["access_token"]
        .as_str()
        .ok_or_else(|| AppError::Internal("refresh response missing access_token".into()))?;

    let new_refresh_token = token_resp["refresh_token"].as_str();

    let expires_in = token_resp["expires_in"].as_u64();
    let new_expires_at = expires_in
        .map(|secs| (chrono::Utc::now() + chrono::Duration::seconds(secs as i64)).to_rfc3339());

    // Update the stored session
    super::sessions::store_dpop_session(
        pool,
        backend,
        encryption_key,
        &creds.session.id,
        &creds.session.api_client_id,
        &creds.session.dpop_key_id,
        &creds.session.user_did,
        new_access_token,
        new_refresh_token.or(creds.session.refresh_token.as_deref()),
        new_expires_at
            .as_deref()
            .or(creds.session.token_expires_at.as_deref()),
        &creds.session.scopes,
        creds.session.pds_url.as_deref(),
        creds.session.issuer.as_deref(),
    )
    .await?;

    // Update the in-memory credentials
    creds.session.access_token = new_access_token.to_string();
    if let Some(rt) = new_refresh_token {
        creds.session.refresh_token = Some(rt.to_string());
    }
    if let Some(ref exp) = new_expires_at {
        creds.session.token_expires_at = Some(exp.clone());
    }

    tracing::info!(
        user_did = %creds.session.user_did,
        api_client_id = %creds.session.api_client_id,
        "refreshed DPoP access token"
    );

    Ok(())
}

/// Discover the token endpoint from an OAuth authorization server's metadata.
async fn discover_token_endpoint(http: &reqwest::Client, issuer: &str) -> Result<String, AppError> {
    let metadata_url = format!(
        "{}/.well-known/oauth-authorization-server",
        issuer.trim_end_matches('/')
    );

    let resp =
        http.get(&metadata_url).send().await.map_err(|e| {
            AppError::Internal(format!("failed to fetch auth server metadata: {e}"))
        })?;

    if !resp.status().is_success() {
        return Err(AppError::Internal(format!(
            "auth server metadata returned {}",
            resp.status()
        )));
    }

    let metadata: serde_json::Value = resp
        .json()
        .await
        .map_err(|e| AppError::Internal(format!("invalid auth server metadata: {e}")))?;

    metadata["token_endpoint"]
        .as_str()
        .map(|s| s.to_string())
        .ok_or_else(|| AppError::Internal("auth server metadata missing token_endpoint".into()))
}

/// Look up the client_id_url for an API client by its internal ID.
async fn lookup_client_id_url(
    pool: &sqlx::AnyPool,
    backend: DatabaseBackend,
    api_client_id: &str,
) -> Result<String, AppError> {
    let sql = crate::db::adapt_sql(
        "SELECT client_id_url FROM api_clients WHERE id = ?",
        backend,
    );
    let row: Option<(String,)> = sqlx::query_as(&sql)
        .bind(api_client_id)
        .fetch_optional(pool)
        .await
        .map_err(|e| AppError::Internal(format!("failed to look up API client: {e}")))?;

    row.map(|(url,)| url)
        .ok_or_else(|| AppError::Internal("API client not found".into()))
}

/// Generate a DPoP proof JWT for a PDS request.
pub fn generate_dpop_proof(
    private_jwk: &serde_json::Value,
    method: &str,
    url: &str,
    access_token: &str,
    nonce: Option<&str>,
) -> Result<String, AppError> {
    let ath = URL_SAFE_NO_PAD.encode(Sha256::digest(access_token.as_bytes()));
    generate_dpop_proof_inner(private_jwk, method, url, Some(&ath), nonce)
}

/// Generate a DPoP proof JWT without an `ath` claim (for token endpoint requests).
fn generate_dpop_proof_no_ath(
    private_jwk: &serde_json::Value,
    method: &str,
    url: &str,
    nonce: Option<&str>,
) -> Result<String, AppError> {
    generate_dpop_proof_inner(private_jwk, method, url, None, nonce)
}

fn generate_dpop_proof_inner(
    private_jwk: &serde_json::Value,
    method: &str,
    url: &str,
    ath: Option<&str>,
    nonce: Option<&str>,
) -> Result<String, AppError> {
    let d_b64 = private_jwk["d"]
        .as_str()
        .ok_or_else(|| AppError::Internal("DPoP key missing d parameter".into()))?;
    let x_b64 = private_jwk["x"]
        .as_str()
        .ok_or_else(|| AppError::Internal("DPoP key missing x parameter".into()))?;
    let y_b64 = private_jwk["y"]
        .as_str()
        .ok_or_else(|| AppError::Internal("DPoP key missing y parameter".into()))?;

    let d_bytes = URL_SAFE_NO_PAD
        .decode(d_b64)
        .map_err(|_| AppError::Internal("invalid DPoP key d parameter".into()))?;

    let signing_key = SigningKey::from_bytes((&d_bytes[..]).into())
        .map_err(|e| AppError::Internal(format!("invalid DPoP signing key: {e}")))?;

    let public_jwk = serde_json::json!({
        "kty": "EC",
        "crv": "P-256",
        "x": x_b64,
        "y": y_b64,
    });

    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();

    let header = serde_json::json!({
        "alg": "ES256",
        "typ": "dpop+jwt",
        "jwk": public_jwk,
    });

    let mut payload = serde_json::json!({
        "htm": method,
        "htu": url,
        "iat": now,
        "jti": format!("{:x}", rand::random::<u64>()),
    });
    if let Some(ath) = ath {
        payload["ath"] = serde_json::json!(ath);
    }
    if let Some(nonce) = nonce {
        payload["nonce"] = serde_json::json!(nonce);
    }

    let header_b64 = URL_SAFE_NO_PAD.encode(serde_json::to_vec(&header).unwrap());
    let payload_b64 = URL_SAFE_NO_PAD.encode(serde_json::to_vec(&payload).unwrap());

    let message = format!("{}.{}", header_b64, payload_b64);
    let signature: p256::ecdsa::Signature = signing_key.sign(message.as_bytes());
    let sig_b64 = URL_SAFE_NO_PAD.encode(signature.to_bytes());

    Ok(format!("{}.{}.{}", header_b64, payload_b64, sig_b64))
}

/// Resolve a user's PDS URL from their DID document.
async fn resolve_pds_from_did(
    http: &reqwest::Client,
    plc_url: &str,
    did: &str,
) -> Result<String, AppError> {
    let url = if did.starts_with("did:plc:") {
        format!("{}/{}", plc_url.trim_end_matches('/'), did)
    } else if did.starts_with("did:web:") {
        let host = did.strip_prefix("did:web:").unwrap();
        format!("https://{}/.well-known/did.json", host)
    } else {
        return Err(AppError::Internal(format!("unsupported DID method: {did}")));
    };

    let resp = http
        .get(&url)
        .send()
        .await
        .map_err(|e| AppError::Internal(format!("failed to resolve DID: {e}")))?;

    let doc: serde_json::Value = resp
        .json()
        .await
        .map_err(|e| AppError::Internal(format!("failed to parse DID document: {e}")))?;

    let services = doc["service"]
        .as_array()
        .ok_or_else(|| AppError::Internal("DID document missing service array".into()))?;

    for service in services {
        let id = service["id"].as_str().unwrap_or("");
        if (id == "#atproto_pds" || id.ends_with("#atproto_pds"))
            && let Some(endpoint) = service["serviceEndpoint"].as_str()
        {
            return Ok(endpoint.to_string());
        }
    }

    Err(AppError::Internal(format!(
        "no #atproto_pds service found in DID document for {did}"
    )))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generate_dpop_proof_produces_valid_jwt() {
        let keypair = super::super::keys::generate_dpop_keypair().unwrap();

        let proof = generate_dpop_proof(
            &keypair.private_jwk,
            "POST",
            "https://pds.example.com/xrpc/com.atproto.repo.createRecord",
            "test-access-token",
            None,
        )
        .unwrap();

        let parts: Vec<&str> = proof.split('.').collect();
        assert_eq!(parts.len(), 3);

        let header_bytes = URL_SAFE_NO_PAD.decode(parts[0]).unwrap();
        let header: serde_json::Value = serde_json::from_slice(&header_bytes).unwrap();
        assert_eq!(header["alg"], "ES256");
        assert_eq!(header["typ"], "dpop+jwt");
        assert_eq!(header["jwk"]["kty"], "EC");

        let payload_bytes = URL_SAFE_NO_PAD.decode(parts[1]).unwrap();
        let payload: serde_json::Value = serde_json::from_slice(&payload_bytes).unwrap();
        assert_eq!(payload["htm"], "POST");
        assert_eq!(
            payload["htu"],
            "https://pds.example.com/xrpc/com.atproto.repo.createRecord"
        );
        assert!(payload["iat"].is_number());
        assert!(payload["ath"].is_string());
        assert!(payload["jti"].is_string());
    }

    #[test]
    fn generate_dpop_proof_includes_nonce() {
        let keypair = super::super::keys::generate_dpop_keypair().unwrap();

        let proof = generate_dpop_proof(
            &keypair.private_jwk,
            "POST",
            "https://pds.example.com/xrpc/test",
            "token",
            Some("server-nonce-123"),
        )
        .unwrap();

        let parts: Vec<&str> = proof.split('.').collect();
        let payload_bytes = URL_SAFE_NO_PAD.decode(parts[1]).unwrap();
        let payload: serde_json::Value = serde_json::from_slice(&payload_bytes).unwrap();
        assert_eq!(payload["nonce"], "server-nonce-123");
    }

    #[test]
    fn generate_dpop_proof_no_ath_omits_ath() {
        let keypair = super::super::keys::generate_dpop_keypair().unwrap();

        let proof = generate_dpop_proof_no_ath(
            &keypair.private_jwk,
            "POST",
            "https://auth.example.com/oauth/token",
            None,
        )
        .unwrap();

        let parts: Vec<&str> = proof.split('.').collect();
        let payload_bytes = URL_SAFE_NO_PAD.decode(parts[1]).unwrap();
        let payload: serde_json::Value = serde_json::from_slice(&payload_bytes).unwrap();
        assert!(payload.get("ath").is_none());
        assert!(payload["htm"].is_string());
        assert!(payload["htu"].is_string());
    }

    #[test]
    fn generated_proof_validates_against_own_key() {
        let keypair = super::super::keys::generate_dpop_keypair().unwrap();
        let url = "https://pds.example.com/xrpc/test.method";
        let token = "my-access-token";

        let proof = generate_dpop_proof(&keypair.private_jwk, "POST", url, token, None).unwrap();

        let result = super::super::dpop_proof::validate_dpop_proof(
            &proof,
            "POST",
            url,
            token,
            &keypair.thumbprint,
        );
        assert!(result.is_ok(), "validation failed: {:?}", result.err());
    }
}
