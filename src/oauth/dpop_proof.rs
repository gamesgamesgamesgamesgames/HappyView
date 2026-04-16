use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use p256::ecdsa::{Signature, VerifyingKey, signature::Verifier};
use serde::Deserialize;
use sha2::{Digest, Sha256};

use crate::error::AppError;

#[derive(Debug, Deserialize)]
struct DpopHeader {
    alg: String,
    typ: String,
    jwk: serde_json::Value,
}

#[derive(Debug, Deserialize)]
#[allow(dead_code)]
struct DpopPayload {
    htm: String,
    htu: String,
    iat: u64,
    ath: Option<String>,
    jti: String,
}

/// Validate a DPoP proof JWT.
///
/// Checks:
/// - `typ` is `dpop+jwt`
/// - `alg` is `ES256`
/// - `htm` matches the request method
/// - `htu` matches the request URL (scheme + host + path, no query/fragment)
/// - `iat` is within 5 minutes of now
/// - `ath` matches SHA256(access_token) if provided
/// - Signature is valid against the embedded JWK
/// - JWK thumbprint matches the expected thumbprint
pub fn validate_dpop_proof(
    proof_jwt: &str,
    expected_method: &str,
    expected_url: &str,
    access_token: &str,
    expected_thumbprint: &str,
) -> Result<(), AppError> {
    let parts: Vec<&str> = proof_jwt.split('.').collect();
    if parts.len() != 3 {
        return Err(AppError::Auth("invalid DPoP proof format".into()));
    }

    // Decode header
    let header_bytes = URL_SAFE_NO_PAD
        .decode(parts[0])
        .map_err(|_| AppError::Auth("invalid DPoP proof header encoding".into()))?;
    let header: DpopHeader = serde_json::from_slice(&header_bytes)
        .map_err(|_| AppError::Auth("invalid DPoP proof header".into()))?;

    // Check typ and alg
    if header.typ != "dpop+jwt" {
        return Err(AppError::Auth("DPoP proof typ must be dpop+jwt".into()));
    }
    if header.alg != "ES256" {
        return Err(AppError::Auth("DPoP proof alg must be ES256".into()));
    }

    // Decode payload
    let payload_bytes = URL_SAFE_NO_PAD
        .decode(parts[1])
        .map_err(|_| AppError::Auth("invalid DPoP proof payload encoding".into()))?;
    let payload: DpopPayload = serde_json::from_slice(&payload_bytes)
        .map_err(|_| AppError::Auth("invalid DPoP proof payload".into()))?;

    // Check htm
    if !payload.htm.eq_ignore_ascii_case(expected_method) {
        return Err(AppError::Auth("DPoP proof htm mismatch".into()));
    }

    // Check htu (strip query and fragment from expected URL for comparison)
    let expected_htu = strip_query_fragment(expected_url);
    if payload.htu != expected_htu {
        return Err(AppError::Auth("DPoP proof htu mismatch".into()));
    }

    // Check iat (within 5 minutes)
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();
    if now.abs_diff(payload.iat) > 300 {
        return Err(AppError::Auth(
            "DPoP proof expired or too far in the future".into(),
        ));
    }

    // Check ath (access token hash) — required per RFC 9449 section 4.2
    let expected_ath = URL_SAFE_NO_PAD.encode(Sha256::digest(access_token.as_bytes()));
    let ath = payload
        .ath
        .as_ref()
        .ok_or_else(|| AppError::Auth("DPoP proof missing required ath claim".into()))?;
    if *ath != expected_ath {
        return Err(AppError::Auth("DPoP proof ath mismatch".into()));
    }

    // Verify JWK thumbprint matches expected
    let proof_thumbprint = super::keys::compute_jwk_thumbprint(&header.jwk)?;
    if proof_thumbprint != expected_thumbprint {
        return Err(AppError::Auth(
            "DPoP proof key does not match session".into(),
        ));
    }

    // Verify signature
    let message = format!("{}.{}", parts[0], parts[1]);
    let sig_bytes = URL_SAFE_NO_PAD
        .decode(parts[2])
        .map_err(|_| AppError::Auth("invalid DPoP proof signature encoding".into()))?;

    verify_es256_jwk(&message, &sig_bytes, &header.jwk)?;

    Ok(())
}

/// Verify an ES256 signature using a JWK public key.
fn verify_es256_jwk(
    message: &str,
    sig_bytes: &[u8],
    jwk: &serde_json::Value,
) -> Result<(), AppError> {
    let x_b64 = jwk["x"]
        .as_str()
        .ok_or_else(|| AppError::Auth("DPoP JWK missing x".into()))?;
    let y_b64 = jwk["y"]
        .as_str()
        .ok_or_else(|| AppError::Auth("DPoP JWK missing y".into()))?;

    let x_bytes = URL_SAFE_NO_PAD
        .decode(x_b64)
        .map_err(|_| AppError::Auth("invalid DPoP JWK x".into()))?;
    let y_bytes = URL_SAFE_NO_PAD
        .decode(y_b64)
        .map_err(|_| AppError::Auth("invalid DPoP JWK y".into()))?;

    // Build SEC1 uncompressed point: 0x04 || x || y
    let mut sec1 = Vec::with_capacity(1 + 32 + 32);
    sec1.push(0x04);
    sec1.extend_from_slice(&x_bytes);
    sec1.extend_from_slice(&y_bytes);

    let verifying_key = VerifyingKey::from_sec1_bytes(&sec1)
        .map_err(|_| AppError::Auth("invalid DPoP public key".into()))?;

    let signature = Signature::from_bytes(sig_bytes.into())
        .map_err(|_| AppError::Auth("invalid DPoP signature format".into()))?;

    verifying_key
        .verify(message.as_bytes(), &signature)
        .map_err(|_| AppError::Auth("DPoP proof signature verification failed".into()))?;

    Ok(())
}

/// Strip query string and fragment from a URL (per RFC 9449 section 4.2).
fn strip_query_fragment(url: &str) -> &str {
    let end = url
        .find('#')
        .unwrap_or(url.len())
        .min(url.find('?').unwrap_or(url.len()));
    &url[..end]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn strip_query_fragment_works() {
        assert_eq!(
            strip_query_fragment("https://example.com/path"),
            "https://example.com/path"
        );
        assert_eq!(
            strip_query_fragment("https://example.com/path?query=1"),
            "https://example.com/path"
        );
        assert_eq!(
            strip_query_fragment("https://example.com/path#frag"),
            "https://example.com/path"
        );
        assert_eq!(
            strip_query_fragment("https://example.com/path?q=1#f"),
            "https://example.com/path"
        );
    }

    #[test]
    fn rejects_invalid_format() {
        let result = validate_dpop_proof(
            "not.a.valid.jwt.too-many",
            "GET",
            "https://example.com",
            "token",
            "thumb",
        );
        assert!(result.is_err());
    }

    #[test]
    fn rejects_non_dpop_typ() {
        // Build a JWT with typ: "JWT" instead of "dpop+jwt"
        let header = URL_SAFE_NO_PAD.encode(r#"{"alg":"ES256","typ":"JWT","jwk":{}}"#);
        let payload = URL_SAFE_NO_PAD
            .encode(r#"{"htm":"GET","htu":"https://example.com","iat":0,"jti":"x"}"#);
        let fake_sig = URL_SAFE_NO_PAD.encode(b"fakesig");
        let jwt = format!("{}.{}.{}", header, payload, fake_sig);

        let result = validate_dpop_proof(&jwt, "GET", "https://example.com", "token", "thumb");
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("dpop+jwt"));
    }
}
