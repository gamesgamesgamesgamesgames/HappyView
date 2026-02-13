use axum::body::Bytes;
use axum::extract::State;
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use base64::Engine;
use p256::pkcs8::EncodePrivateKey;
use serde::Deserialize;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};

use crate::AppState;
use crate::auth::Claims;
use crate::error::AppError;

// ---------------------------------------------------------------------------
// AT URI parsing
// ---------------------------------------------------------------------------

/// Extract the DID from an AT URI (at://did/collection/rkey).
pub(crate) fn parse_did_from_at_uri(uri: &str) -> Result<String, AppError> {
    let stripped = uri
        .strip_prefix("at://")
        .ok_or_else(|| AppError::Internal("AT URI must start with at://".into()))?;

    stripped
        .split('/')
        .next()
        .map(|s| s.to_string())
        .ok_or_else(|| AppError::Internal("invalid AT URI".into()))
}

// ---------------------------------------------------------------------------
// AIP session types
// ---------------------------------------------------------------------------

#[derive(Deserialize)]
pub(crate) struct AtpSession {
    pub(crate) access_token: String,
    pub(crate) pds_endpoint: String,
    pub(crate) dpop_jwk: DpopJwk,
}

#[derive(Deserialize)]
pub(crate) struct DpopJwk {
    pub(crate) x: String,
    pub(crate) y: String,
    pub(crate) d: String,
}

// ---------------------------------------------------------------------------
// DPoP proof generation
// ---------------------------------------------------------------------------

#[derive(serde::Serialize)]
struct DpopClaims {
    jti: String,
    htm: String,
    htu: String,
    iat: i64,
    exp: i64,
    ath: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    nonce: Option<String>,
}

/// Fetch the user's AT Protocol session (PDS credentials) from AIP.
pub(crate) async fn get_atp_session(state: &AppState, token: &str) -> Result<AtpSession, AppError> {
    let url = format!(
        "{}/api/atprotocol/session",
        state.config.aip_url.trim_end_matches('/')
    );

    let resp = state
        .http
        .get(&url)
        .header("authorization", format!("Bearer {token}"))
        .send()
        .await
        .map_err(|e| AppError::Internal(format!("AIP session request failed: {e}")))?;

    if !resp.status().is_success() {
        return Err(AppError::Auth(format!(
            "AIP session returned {}",
            resp.status()
        )));
    }

    resp.json()
        .await
        .map_err(|e| AppError::Internal(format!("invalid AIP session response: {e}")))
}

/// Generate a DPoP proof JWT for a PDS request.
pub(crate) fn generate_dpop_proof(
    method: &str,
    url: &str,
    dpop_jwk: &DpopJwk,
    access_token: &str,
    nonce: Option<&str>,
) -> Result<String, AppError> {
    // Decode the private key from base64url
    let d_bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(&dpop_jwk.d)
        .map_err(|e| AppError::Internal(format!("invalid DPoP key d: {e}")))?;

    let secret_key = p256::SecretKey::from_slice(&d_bytes)
        .map_err(|e| AppError::Internal(format!("invalid P-256 key: {e}")))?;

    let pkcs8_der = secret_key
        .to_pkcs8_der()
        .map_err(|e| AppError::Internal(format!("PKCS#8 conversion failed: {e}")))?;

    let encoding_key = jsonwebtoken::EncodingKey::from_ec_der(pkcs8_der.as_bytes());

    // Public JWK for the header (no private component)
    let public_jwk = jsonwebtoken::jwk::Jwk {
        common: jsonwebtoken::jwk::CommonParameters {
            public_key_use: None,
            key_operations: None,
            key_algorithm: None,
            key_id: None,
            x509_url: None,
            x509_chain: None,
            x509_sha1_fingerprint: None,
            x509_sha256_fingerprint: None,
        },
        algorithm: jsonwebtoken::jwk::AlgorithmParameters::EllipticCurve(
            jsonwebtoken::jwk::EllipticCurveKeyParameters {
                key_type: jsonwebtoken::jwk::EllipticCurveKeyType::EC,
                curve: jsonwebtoken::jwk::EllipticCurve::P256,
                x: dpop_jwk.x.clone(),
                y: dpop_jwk.y.clone(),
            },
        ),
    };

    let mut header = jsonwebtoken::Header::new(jsonwebtoken::Algorithm::ES256);
    header.typ = Some("dpop+jwt".to_string());
    header.jwk = Some(public_jwk);

    // Access token hash (ath)
    let ath_hash = Sha256::digest(access_token.as_bytes());
    let ath = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(ath_hash);

    let now = chrono::Utc::now().timestamp();
    let claims = DpopClaims {
        jti: uuid::Uuid::new_v4().to_string(),
        htm: method.to_uppercase(),
        htu: url.to_string(),
        iat: now,
        exp: now + 300,
        ath,
        nonce: nonce.map(|n| n.to_string()),
    };

    jsonwebtoken::encode(&header, &claims, &encoding_key)
        .map_err(|e| AppError::Internal(format!("DPoP proof signing failed: {e}")))
}

// ---------------------------------------------------------------------------
// PDS request helpers with DPoP + nonce retry
// ---------------------------------------------------------------------------

/// Forward a PDS response back to the client, preserving status and body.
pub(crate) async fn forward_pds_response(resp: reqwest::Response) -> Result<Response, AppError> {
    let status = resp.status();
    let body = resp
        .bytes()
        .await
        .map_err(|e| AppError::Internal(format!("failed to read PDS response: {e}")))?;

    let axum_status = StatusCode::from_u16(status.as_u16()).unwrap();

    if status.is_success() {
        Ok((
            axum_status,
            [(axum::http::header::CONTENT_TYPE, "application/json")],
            body,
        )
            .into_response())
    } else {
        let body_str = String::from_utf8_lossy(&body);
        tracing::warn!(status = %axum_status, body = %body_str, "PDS returned error");
        Err(AppError::PdsError(axum_status, body))
    }
}

/// POST JSON to a PDS XRPC endpoint with DPoP auth and nonce retry.
/// Returns the raw reqwest::Response so callers can inspect the body.
pub(crate) async fn pds_post_json_raw(
    state: &AppState,
    session: &AtpSession,
    xrpc_method: &str,
    body: &Value,
) -> Result<reqwest::Response, AppError> {
    let url = format!(
        "{}/xrpc/{xrpc_method}",
        session.pds_endpoint.trim_end_matches('/')
    );

    let dpop = generate_dpop_proof("POST", &url, &session.dpop_jwk, &session.access_token, None)?;

    let resp = state
        .http
        .post(&url)
        .header("authorization", format!("DPoP {}", session.access_token))
        .header("dpop", &dpop)
        .json(body)
        .send()
        .await
        .map_err(|e| AppError::Internal(format!("PDS request failed: {e}")))?;

    // Retry with nonce if PDS requires it
    if resp.status() == reqwest::StatusCode::UNAUTHORIZED
        && let Some(nonce) = resp
            .headers()
            .get("dpop-nonce")
            .and_then(|v| v.to_str().ok())
    {
        let nonce = nonce.to_string();
        tracing::debug!("retrying with DPoP nonce");

        let dpop = generate_dpop_proof(
            "POST",
            &url,
            &session.dpop_jwk,
            &session.access_token,
            Some(&nonce),
        )?;

        let resp = state
            .http
            .post(&url)
            .header("authorization", format!("DPoP {}", session.access_token))
            .header("dpop", &dpop)
            .json(body)
            .send()
            .await
            .map_err(|e| AppError::Internal(format!("PDS request retry failed: {e}")))?;

        return Ok(resp);
    }

    Ok(resp)
}

/// POST a binary blob to the PDS with DPoP auth and nonce retry.
async fn pds_post_blob(
    state: &AppState,
    session: &AtpSession,
    content_type: &str,
    blob: Bytes,
) -> Result<Response, AppError> {
    let url = format!(
        "{}/xrpc/com.atproto.repo.uploadBlob",
        session.pds_endpoint.trim_end_matches('/')
    );

    let dpop = generate_dpop_proof("POST", &url, &session.dpop_jwk, &session.access_token, None)?;

    let resp = state
        .http
        .post(&url)
        .header("authorization", format!("DPoP {}", session.access_token))
        .header("dpop", &dpop)
        .header("content-type", content_type)
        .body(blob.clone())
        .send()
        .await
        .map_err(|e| AppError::Internal(format!("PDS uploadBlob failed: {e}")))?;

    if resp.status() == reqwest::StatusCode::UNAUTHORIZED
        && let Some(nonce) = resp
            .headers()
            .get("dpop-nonce")
            .and_then(|v| v.to_str().ok())
    {
        let nonce = nonce.to_string();
        tracing::debug!("retrying uploadBlob with DPoP nonce");

        let dpop = generate_dpop_proof(
            "POST",
            &url,
            &session.dpop_jwk,
            &session.access_token,
            Some(&nonce),
        )?;

        let resp = state
            .http
            .post(&url)
            .header("authorization", format!("DPoP {}", session.access_token))
            .header("dpop", &dpop)
            .header("content-type", content_type)
            .body(blob)
            .send()
            .await
            .map_err(|e| AppError::Internal(format!("PDS uploadBlob retry failed: {e}")))?;

        return forward_pds_response(resp).await;
    }

    forward_pds_response(resp).await
}

// ---------------------------------------------------------------------------
// Public handlers
// ---------------------------------------------------------------------------

pub async fn upload_blob(
    State(state): State<AppState>,
    claims: Claims,
    headers: HeaderMap,
    body: Bytes,
) -> Result<Response, AppError> {
    let session = get_atp_session(&state, claims.token()).await?;

    let content_type = headers
        .get("content-type")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("application/octet-stream");

    pds_post_blob(&state, &session, content_type, body).await
}

/// Walk `media[]` and add a `url` field to each blob so the frontend can
/// display images directly.
pub(crate) fn enrich_media_blobs(record: &mut Value, pds: &str, did: &str) {
    let media = match record.get_mut("media").and_then(|m| m.as_array_mut()) {
        Some(arr) => arr,
        None => return,
    };

    let pds_base = pds.trim_end_matches('/');

    for item in media.iter_mut() {
        let cid = item
            .get("blob")
            .and_then(|b| b.get("ref"))
            .and_then(|r| r.get("$link"))
            .and_then(|l| l.as_str())
            .map(|s| s.to_string());

        if let Some(cid) = cid
            && let Some(blob) = item.get_mut("blob")
            && let Some(obj) = blob.as_object_mut()
        {
            obj.insert(
                "url".to_string(),
                json!(format!(
                    "{pds_base}/xrpc/com.atproto.sync.getBlob?did={did}&cid={cid}"
                )),
            );
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // -----------------------------------------------------------------------
    // parse_did_from_at_uri
    // -----------------------------------------------------------------------

    #[test]
    fn parse_did_from_valid_at_uri() {
        let did = parse_did_from_at_uri("at://did:plc:abc123/app.bsky.feed.post/3k2bqxyz").unwrap();
        assert_eq!(did, "did:plc:abc123");
    }

    #[test]
    fn parse_did_from_uri_with_no_rkey() {
        let did = parse_did_from_at_uri("at://did:plc:abc123/collection").unwrap();
        assert_eq!(did, "did:plc:abc123");
    }

    #[test]
    fn parse_did_from_did_web_uri() {
        let did = parse_did_from_at_uri("at://did:web:example.com/collection/rkey").unwrap();
        assert_eq!(did, "did:web:example.com");
    }

    #[test]
    fn parse_did_from_uri_missing_prefix() {
        let result = parse_did_from_at_uri("did:plc:abc123/collection/rkey");
        assert!(result.is_err());
    }

    // -----------------------------------------------------------------------
    // enrich_media_blobs
    // -----------------------------------------------------------------------

    #[test]
    fn enrich_media_adds_url() {
        let mut record = json!({
            "media": [{
                "blob": {
                    "ref": { "$link": "bafyreiabc" },
                    "mimeType": "image/jpeg",
                    "size": 1024
                }
            }]
        });

        enrich_media_blobs(&mut record, "https://pds.example.com", "did:plc:test");

        let url = record["media"][0]["blob"]["url"].as_str().unwrap();
        assert_eq!(
            url,
            "https://pds.example.com/xrpc/com.atproto.sync.getBlob?did=did:plc:test&cid=bafyreiabc"
        );
    }

    #[test]
    fn enrich_media_noop_without_media() {
        let mut record = json!({"title": "test"});
        enrich_media_blobs(&mut record, "https://pds.example.com", "did:plc:test");
        assert!(record.get("media").is_none());
    }

    #[test]
    fn enrich_media_skips_items_without_ref() {
        let mut record = json!({
            "media": [{
                "blob": { "mimeType": "image/png" }
            }]
        });

        enrich_media_blobs(&mut record, "https://pds.example.com", "did:plc:test");
        assert!(record["media"][0]["blob"].get("url").is_none());
    }

    #[test]
    fn enrich_media_handles_multiple_items() {
        let mut record = json!({
            "media": [
                { "blob": { "ref": { "$link": "cid1" } } },
                { "blob": { "ref": { "$link": "cid2" } } }
            ]
        });

        enrich_media_blobs(&mut record, "https://pds.example.com/", "did:plc:x");

        let url1 = record["media"][0]["blob"]["url"].as_str().unwrap();
        let url2 = record["media"][1]["blob"]["url"].as_str().unwrap();
        assert!(url1.contains("cid1"));
        assert!(url2.contains("cid2"));
    }

    #[test]
    fn enrich_media_trims_trailing_slash() {
        let mut record = json!({
            "media": [{
                "blob": { "ref": { "$link": "bafytest" } }
            }]
        });

        enrich_media_blobs(&mut record, "https://pds.example.com/", "did:plc:test");

        let url = record["media"][0]["blob"]["url"].as_str().unwrap();
        assert!(url.starts_with("https://pds.example.com/xrpc/"));
        assert!(!url.contains("//xrpc"));
    }

    // -----------------------------------------------------------------------
    // generate_dpop_proof
    // -----------------------------------------------------------------------

    fn test_dpop_jwk() -> DpopJwk {
        use p256::elliptic_curve::rand_core::OsRng;
        use p256::elliptic_curve::sec1::ToEncodedPoint;
        // Generate a valid P-256 key for testing
        let secret = p256::SecretKey::random(&mut OsRng);
        let public = secret.public_key();
        let point = public.to_encoded_point(false);

        DpopJwk {
            x: base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(point.x().unwrap()),
            y: base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(point.y().unwrap()),
            d: base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(secret.to_bytes()),
        }
    }

    #[test]
    fn dpop_proof_produces_valid_jwt_structure() {
        let jwk = test_dpop_jwk();
        let token = generate_dpop_proof(
            "POST",
            "https://pds.example.com/xrpc/test",
            &jwk,
            "access-tok",
            None,
        )
        .unwrap();

        let parts: Vec<&str> = token.split('.').collect();
        assert_eq!(parts.len(), 3, "JWT should have 3 parts");
    }

    #[test]
    fn dpop_proof_header_has_correct_fields() {
        let jwk = test_dpop_jwk();
        let token = generate_dpop_proof(
            "POST",
            "https://pds.example.com/xrpc/test",
            &jwk,
            "access-tok",
            None,
        )
        .unwrap();

        let header_b64 = token.split('.').next().unwrap();
        let header_bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .decode(header_b64)
            .unwrap();
        let header: serde_json::Value = serde_json::from_slice(&header_bytes).unwrap();

        assert_eq!(header["typ"], "dpop+jwt");
        assert_eq!(header["alg"], "ES256");
        assert!(header.get("jwk").is_some());
    }

    #[test]
    fn dpop_proof_claims_have_correct_fields() {
        let jwk = test_dpop_jwk();
        let token = generate_dpop_proof(
            "GET",
            "https://pds.example.com/xrpc/test",
            &jwk,
            "my-access-token",
            None,
        )
        .unwrap();

        let payload_b64 = token.split('.').nth(1).unwrap();
        let payload_bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .decode(payload_b64)
            .unwrap();
        let claims: serde_json::Value = serde_json::from_slice(&payload_bytes).unwrap();

        assert_eq!(claims["htm"], "GET");
        assert_eq!(claims["htu"], "https://pds.example.com/xrpc/test");
        assert!(claims.get("jti").is_some());
        assert!(claims.get("iat").is_some());
        assert!(claims.get("exp").is_some());
        assert!(claims.get("ath").is_some());
        assert!(claims.get("nonce").is_none());
    }

    #[test]
    fn dpop_proof_includes_nonce_when_provided() {
        let jwk = test_dpop_jwk();
        let token = generate_dpop_proof(
            "POST",
            "https://pds.example.com/xrpc/test",
            &jwk,
            "tok",
            Some("abc123"),
        )
        .unwrap();

        let payload_b64 = token.split('.').nth(1).unwrap();
        let payload_bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .decode(payload_b64)
            .unwrap();
        let claims: serde_json::Value = serde_json::from_slice(&payload_bytes).unwrap();

        assert_eq!(claims["nonce"], "abc123");
    }

    #[test]
    fn dpop_proof_ath_is_sha256_of_access_token() {
        let jwk = test_dpop_jwk();
        let access_token = "test-access-token";
        let token =
            generate_dpop_proof("POST", "https://example.com", &jwk, access_token, None).unwrap();

        let payload_b64 = token.split('.').nth(1).unwrap();
        let payload_bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .decode(payload_b64)
            .unwrap();
        let claims: serde_json::Value = serde_json::from_slice(&payload_bytes).unwrap();

        let expected_hash = Sha256::digest(access_token.as_bytes());
        let expected_ath = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(expected_hash);
        assert_eq!(claims["ath"], expected_ath);
    }

    #[test]
    fn dpop_proof_invalid_key_returns_error() {
        let jwk = DpopJwk {
            x: "invalid".into(),
            y: "invalid".into(),
            d: "invalid".into(),
        };
        let result = generate_dpop_proof("POST", "https://example.com", &jwk, "tok", None);
        assert!(result.is_err());
    }
}
