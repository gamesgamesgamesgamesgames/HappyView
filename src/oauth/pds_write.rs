use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use p256::ecdsa::{SigningKey, signature::Signer};
use sha2::{Digest, Sha256};

use crate::db::DatabaseBackend;
use crate::error::AppError;
use crate::plugin::encryption::decrypt;

/// Make an authenticated POST to a PDS XRPC endpoint using a DPoP session.
#[allow(clippy::too_many_arguments)]
pub async fn dpop_pds_post(
    http: &reqwest::Client,
    pool: &sqlx::AnyPool,
    backend: DatabaseBackend,
    encryption_key: &[u8; 32],
    plc_url: &str,
    api_client_id: &str,
    user_did: &str,
    xrpc_method: &str,
    body: &serde_json::Value,
) -> Result<reqwest::Response, AppError> {
    let session =
        super::sessions::get_dpop_session(pool, backend, encryption_key, api_client_id, user_did)
            .await?;

    let pds_url = match session.pds_url {
        Some(ref url) => url.clone(),
        None => resolve_pds_from_did(http, plc_url, user_did).await?,
    };

    let target_url = format!("{}/xrpc/{}", pds_url.trim_end_matches('/'), xrpc_method);

    // Decrypt the DPoP private key
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

    let proof = generate_dpop_proof(&private_jwk, "POST", &target_url, &session.access_token)?;

    let resp = http
        .post(&target_url)
        .header("Authorization", format!("DPoP {}", session.access_token))
        .header("DPoP", proof)
        .header("Content-Type", "application/json")
        .json(body)
        .send()
        .await
        .map_err(|e| AppError::Internal(format!("PDS request failed: {e}")))?;

    Ok(resp)
}

/// Make an authenticated blob upload to a PDS using a DPoP session.
#[allow(clippy::too_many_arguments)]
pub async fn dpop_pds_post_blob(
    http: &reqwest::Client,
    pool: &sqlx::AnyPool,
    backend: DatabaseBackend,
    encryption_key: &[u8; 32],
    plc_url: &str,
    api_client_id: &str,
    user_did: &str,
    content_type: &str,
    blob: bytes::Bytes,
) -> Result<reqwest::Response, AppError> {
    let session =
        super::sessions::get_dpop_session(pool, backend, encryption_key, api_client_id, user_did)
            .await?;

    let pds_url = match session.pds_url {
        Some(ref url) => url.clone(),
        None => resolve_pds_from_did(http, plc_url, user_did).await?,
    };

    let target_url = format!(
        "{}/xrpc/com.atproto.repo.uploadBlob",
        pds_url.trim_end_matches('/')
    );

    // Decrypt the DPoP private key
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

    let proof = generate_dpop_proof(&private_jwk, "POST", &target_url, &session.access_token)?;

    let resp = http
        .post(&target_url)
        .header("Authorization", format!("DPoP {}", session.access_token))
        .header("DPoP", proof)
        .header("Content-Type", content_type)
        .body(blob)
        .send()
        .await
        .map_err(|e| AppError::Internal(format!("PDS uploadBlob request failed: {e}")))?;

    Ok(resp)
}

/// Generate a DPoP proof JWT for a PDS request.
pub fn generate_dpop_proof(
    private_jwk: &serde_json::Value,
    method: &str,
    url: &str,
    access_token: &str,
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

    let ath = URL_SAFE_NO_PAD.encode(Sha256::digest(access_token.as_bytes()));

    let header = serde_json::json!({
        "alg": "ES256",
        "typ": "dpop+jwt",
        "jwk": public_jwk,
    });

    let payload = serde_json::json!({
        "htm": method,
        "htu": url,
        "iat": now,
        "ath": ath,
        "jti": format!("{:x}", rand::random::<u64>()),
    });

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
    fn generated_proof_validates_against_own_key() {
        let keypair = super::super::keys::generate_dpop_keypair().unwrap();
        let url = "https://pds.example.com/xrpc/test.method";
        let token = "my-access-token";

        let proof = generate_dpop_proof(&keypair.private_jwk, "POST", url, token).unwrap();

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
