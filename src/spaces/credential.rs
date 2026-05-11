use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use p256::ecdsa::{Signature, SigningKey, VerifyingKey, signature::Signer, signature::Verifier};
use serde::{Deserialize, Serialize};

use crate::error::AppError;
use crate::profile;

pub const DEFAULT_CREDENTIAL_TTL_SECS: u64 = 4 * 60 * 60; // 4 hours
pub const GRANT_TTL_SECS: u64 = 5 * 60; // 5 minutes

/// Peek at a JWT's header to check its `typ` field without verifying the signature.
pub fn peek_jwt_typ(token: &str) -> Option<String> {
    let header_b64 = token.split('.').next()?;
    let header_bytes = URL_SAFE_NO_PAD.decode(header_b64).ok()?;
    let header: serde_json::Value = serde_json::from_slice(&header_bytes).ok()?;
    header["typ"].as_str().map(|s| s.to_string())
}

/// Peek at a space credential JWT's payload to extract the `sub` (user DID) without verifying.
pub fn peek_credential_sub(token: &str) -> Option<String> {
    let parts: Vec<&str> = token.split('.').collect();
    if parts.len() != 3 {
        return None;
    }
    let payload_bytes = URL_SAFE_NO_PAD.decode(parts[1]).ok()?;
    let claims: SpaceCredentialClaims = serde_json::from_slice(&payload_bytes).ok()?;
    Some(claims.sub)
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MemberGrantClaims {
    pub sub: String,
    pub space: String,
    pub scope: String,
    pub iat: u64,
    pub exp: u64,
}

pub fn sign_grant(claims: &MemberGrantClaims, secret: &[u8; 32]) -> Result<String, AppError> {
    let header = jsonwebtoken::Header::new(jsonwebtoken::Algorithm::HS256);
    let key = jsonwebtoken::EncodingKey::from_secret(secret);
    jsonwebtoken::encode(&header, claims, &key)
        .map_err(|e| AppError::Internal(format!("failed to sign member grant: {e}")))
}

pub fn verify_grant(token: &str, secret: &[u8; 32]) -> Result<MemberGrantClaims, AppError> {
    let key = jsonwebtoken::DecodingKey::from_secret(secret);
    let mut validation = jsonwebtoken::Validation::new(jsonwebtoken::Algorithm::HS256);
    validation.required_spec_claims.clear();
    validation.validate_exp = false;
    let data = jsonwebtoken::decode::<MemberGrantClaims>(token, &key, &validation)
        .map_err(|e| AppError::Auth(format!("invalid member grant: {e}")))?;

    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();

    if now >= data.claims.exp {
        return Err(AppError::Auth("member grant has expired".into()));
    }

    Ok(data.claims)
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SpaceCredentialClaims {
    pub iss: String,
    pub sub: String,
    pub space: String,
    pub scope: String,
    pub iat: u64,
    pub exp: u64,
}

pub fn sign_credential(
    claims: &SpaceCredentialClaims,
    private_jwk: &serde_json::Value,
) -> Result<String, AppError> {
    let d_b64 = private_jwk["d"]
        .as_str()
        .ok_or_else(|| AppError::Internal("signing key missing d parameter".into()))?;

    let d_bytes = URL_SAFE_NO_PAD
        .decode(d_b64)
        .map_err(|_| AppError::Internal("invalid signing key d parameter".into()))?;

    let signing_key = SigningKey::from_bytes((&d_bytes[..]).into())
        .map_err(|e| AppError::Internal(format!("invalid signing key: {e}")))?;

    let header = serde_json::json!({
        "alg": "ES256",
        "typ": "space_credential",
    });

    let header_b64 = URL_SAFE_NO_PAD.encode(serde_json::to_vec(&header).unwrap());
    let payload_b64 = URL_SAFE_NO_PAD.encode(serde_json::to_vec(claims).unwrap());

    let message = format!("{}.{}", header_b64, payload_b64);
    let signature: Signature = signing_key.sign(message.as_bytes());
    let sig_b64 = URL_SAFE_NO_PAD.encode(signature.to_bytes());

    Ok(format!("{}.{}.{}", header_b64, payload_b64, sig_b64))
}

pub fn verify_credential(
    token: &str,
    public_jwk: &serde_json::Value,
) -> Result<SpaceCredentialClaims, AppError> {
    let parts: Vec<&str> = token.split('.').collect();
    if parts.len() != 3 {
        return Err(AppError::Auth("invalid credential format".into()));
    }

    let header_bytes = URL_SAFE_NO_PAD
        .decode(parts[0])
        .map_err(|_| AppError::Auth("invalid credential header encoding".into()))?;
    let header: serde_json::Value = serde_json::from_slice(&header_bytes)
        .map_err(|_| AppError::Auth("invalid credential header".into()))?;

    if header["alg"].as_str() != Some("ES256") {
        return Err(AppError::Auth("credential alg must be ES256".into()));
    }

    if header["typ"].as_str() != Some("space_credential") {
        return Err(AppError::Auth(
            "credential typ must be space_credential".into(),
        ));
    }

    let x_b64 = public_jwk["x"]
        .as_str()
        .ok_or_else(|| AppError::Auth("public key missing x".into()))?;
    let y_b64 = public_jwk["y"]
        .as_str()
        .ok_or_else(|| AppError::Auth("public key missing y".into()))?;

    let x_bytes = URL_SAFE_NO_PAD
        .decode(x_b64)
        .map_err(|_| AppError::Auth("invalid public key x".into()))?;
    let y_bytes = URL_SAFE_NO_PAD
        .decode(y_b64)
        .map_err(|_| AppError::Auth("invalid public key y".into()))?;

    let mut sec1 = Vec::with_capacity(1 + 32 + 32);
    sec1.push(0x04);
    sec1.extend_from_slice(&x_bytes);
    sec1.extend_from_slice(&y_bytes);

    let verifying_key = VerifyingKey::from_sec1_bytes(&sec1)
        .map_err(|_| AppError::Auth("invalid space credential public key".into()))?;

    let message = format!("{}.{}", parts[0], parts[1]);
    let sig_bytes = URL_SAFE_NO_PAD
        .decode(parts[2])
        .map_err(|_| AppError::Auth("invalid credential signature encoding".into()))?;
    let signature = Signature::from_bytes(sig_bytes.as_slice().into())
        .map_err(|_| AppError::Auth("invalid credential signature format".into()))?;

    verifying_key
        .verify(message.as_bytes(), &signature)
        .map_err(|_| AppError::Auth("credential signature verification failed".into()))?;

    let payload_bytes = URL_SAFE_NO_PAD
        .decode(parts[1])
        .map_err(|_| AppError::Auth("invalid credential payload encoding".into()))?;
    let claims: SpaceCredentialClaims = serde_json::from_slice(&payload_bytes)
        .map_err(|_| AppError::Auth("invalid credential payload".into()))?;

    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();

    if now >= claims.exp {
        return Err(AppError::Auth("credential has expired".into()));
    }

    Ok(claims)
}

/// Convert a multibase-encoded P-256 public key (from a DID doc `publicKeyMultibase`)
/// into a JWK suitable for `verify_credential`.
pub fn multikey_to_p256_jwk(public_key_multibase: &str) -> Result<serde_json::Value, AppError> {
    let (_base, key_bytes) = multibase::decode(public_key_multibase)
        .map_err(|e| AppError::Auth(format!("invalid multibase encoding: {e}")))?;

    // P-256 multicodec prefix: varint 0x1200 → bytes [0x80, 0x24]
    if key_bytes.len() < 2 || key_bytes[0] != 0x80 || key_bytes[1] != 0x24 {
        return Err(AppError::Auth(
            "public key is not a P-256 multicodec key".into(),
        ));
    }

    let compressed = &key_bytes[2..];
    let verifying_key = VerifyingKey::from_sec1_bytes(compressed)
        .map_err(|_| AppError::Auth("invalid P-256 public key bytes".into()))?;

    let point = verifying_key.to_encoded_point(false);
    let x = point
        .x()
        .ok_or_else(|| AppError::Auth("failed to extract x coordinate".into()))?;
    let y = point
        .y()
        .ok_or_else(|| AppError::Auth("failed to extract y coordinate".into()))?;

    Ok(serde_json::json!({
        "kty": "EC",
        "crv": "P-256",
        "x": URL_SAFE_NO_PAD.encode(x),
        "y": URL_SAFE_NO_PAD.encode(y),
    }))
}

/// Verify a space credential JWT issued by an external space host.
///
/// Resolves the issuer's DID document, extracts the `#atproto` signing key,
/// and verifies the JWT signature and expiry.
pub async fn verify_external_credential(
    token: &str,
    http: &reqwest::Client,
    plc_url: &str,
) -> Result<SpaceCredentialClaims, AppError> {
    // Peek at the payload to extract the issuer DID without verifying yet
    let parts: Vec<&str> = token.split('.').collect();
    if parts.len() != 3 {
        return Err(AppError::Auth("invalid credential format".into()));
    }

    let payload_bytes = URL_SAFE_NO_PAD
        .decode(parts[1])
        .map_err(|_| AppError::Auth("invalid credential payload encoding".into()))?;
    let peek: SpaceCredentialClaims = serde_json::from_slice(&payload_bytes)
        .map_err(|_| AppError::Auth("invalid credential payload".into()))?;

    let did_doc = profile::resolve_did_document(http, plc_url, &peek.iss).await?;

    let vm = did_doc
        .verification_method
        .iter()
        .find(|v| v.id.ends_with("#atproto"))
        .ok_or_else(|| AppError::Auth("issuer DID has no #atproto verification method".into()))?;

    let multibase = vm
        .public_key_multibase
        .as_deref()
        .ok_or_else(|| AppError::Auth("verification method missing publicKeyMultibase".into()))?;

    let jwk = multikey_to_p256_jwk(multibase)?;
    verify_credential(token, &jwk)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::oauth::keys::generate_dpop_keypair;

    fn make_claims() -> SpaceCredentialClaims {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        SpaceCredentialClaims {
            iss: "did:plc:spaceowner".into(),
            sub: "did:plc:requester".into(),
            space: "did:plc:spaceowner/com.example.forum/main".into(),
            scope: "read".into(),
            iat: now,
            exp: now + DEFAULT_CREDENTIAL_TTL_SECS,
        }
    }

    #[test]
    fn sign_and_verify_roundtrip() {
        let keypair = generate_dpop_keypair().unwrap();
        let claims = make_claims();

        let token = sign_credential(&claims, &keypair.private_jwk).unwrap();
        let verified = verify_credential(&token, &keypair.public_jwk).unwrap();

        assert_eq!(verified.iss, claims.iss);
        assert_eq!(verified.sub, claims.sub);
        assert_eq!(verified.space, claims.space);
        assert_eq!(verified.scope, claims.scope);
        assert_eq!(verified.iat, claims.iat);
        assert_eq!(verified.exp, claims.exp);
    }

    #[test]
    fn verify_rejects_tampered_payload() {
        let keypair = generate_dpop_keypair().unwrap();
        let claims = make_claims();
        let token = sign_credential(&claims, &keypair.private_jwk).unwrap();

        // Tamper with the payload
        let parts: Vec<&str> = token.split('.').collect();
        let mut payload_bytes = URL_SAFE_NO_PAD.decode(parts[1]).unwrap();
        payload_bytes[0] ^= 0xFF;
        let tampered_payload = URL_SAFE_NO_PAD.encode(&payload_bytes);
        let tampered = format!("{}.{}.{}", parts[0], tampered_payload, parts[2]);

        let result = verify_credential(&tampered, &keypair.public_jwk);
        assert!(result.is_err());
    }

    #[test]
    fn verify_rejects_wrong_key() {
        let keypair1 = generate_dpop_keypair().unwrap();
        let keypair2 = generate_dpop_keypair().unwrap();
        let claims = make_claims();
        let token = sign_credential(&claims, &keypair1.private_jwk).unwrap();

        let result = verify_credential(&token, &keypair2.public_jwk);
        assert!(result.is_err());
    }

    #[test]
    fn verify_rejects_expired() {
        let keypair = generate_dpop_keypair().unwrap();
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let claims = SpaceCredentialClaims {
            iss: "did:plc:owner".into(),
            sub: "did:plc:user".into(),
            space: "did:plc:owner/test/main".into(),
            scope: "read".into(),
            iat: now - 7200,
            exp: now - 3600, // expired 1 hour ago
        };

        let token = sign_credential(&claims, &keypair.private_jwk).unwrap();
        let result = verify_credential(&token, &keypair.public_jwk);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("expired"));
    }

    #[test]
    fn verify_rejects_invalid_format() {
        let keypair = generate_dpop_keypair().unwrap();
        let result = verify_credential("not-a-jwt", &keypair.public_jwk);
        assert!(result.is_err());
    }

    fn test_secret() -> [u8; 32] {
        [0xAB; 32]
    }

    #[test]
    fn grant_sign_and_verify_roundtrip() {
        let secret = test_secret();
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let claims = MemberGrantClaims {
            sub: "did:plc:member".into(),
            space: "ats://did:plc:space/com.example.forum/main".into(),
            scope: "read".into(),
            iat: now,
            exp: now + GRANT_TTL_SECS,
        };

        let token = sign_grant(&claims, &secret).unwrap();
        let verified = verify_grant(&token, &secret).unwrap();

        assert_eq!(verified.sub, claims.sub);
        assert_eq!(verified.space, claims.space);
        assert_eq!(verified.scope, claims.scope);
    }

    #[test]
    fn grant_rejects_wrong_secret() {
        let secret1 = [0xAB; 32];
        let secret2 = [0xCD; 32];
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let claims = MemberGrantClaims {
            sub: "did:plc:member".into(),
            space: "ats://did:plc:space/com.example.forum/main".into(),
            scope: "read".into(),
            iat: now,
            exp: now + GRANT_TTL_SECS,
        };

        let token = sign_grant(&claims, &secret1).unwrap();
        let result = verify_grant(&token, &secret2);
        assert!(result.is_err());
    }

    #[test]
    fn grant_rejects_expired() {
        let secret = test_secret();
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let claims = MemberGrantClaims {
            sub: "did:plc:member".into(),
            space: "ats://did:plc:space/com.example.forum/main".into(),
            scope: "read".into(),
            iat: now - 600,
            exp: now - 300,
        };

        let token = sign_grant(&claims, &secret).unwrap();
        let result = verify_grant(&token, &secret);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("expired"));
    }

    #[test]
    fn credential_has_space_credential_typ() {
        let keypair = generate_dpop_keypair().unwrap();
        let claims = make_claims();
        let token = sign_credential(&claims, &keypair.private_jwk).unwrap();
        assert_eq!(peek_jwt_typ(&token).as_deref(), Some("space_credential"));
    }

    #[test]
    fn peek_jwt_typ_returns_none_for_garbage() {
        assert_eq!(peek_jwt_typ("not-a-jwt"), None);
        assert_eq!(peek_jwt_typ(""), None);
    }

    #[test]
    fn peek_credential_sub_extracts_did() {
        let keypair = generate_dpop_keypair().unwrap();
        let claims = make_claims();
        let token = sign_credential(&claims, &keypair.private_jwk).unwrap();
        assert_eq!(
            peek_credential_sub(&token).as_deref(),
            Some("did:plc:requester")
        );
    }

    #[test]
    fn peek_credential_sub_returns_none_for_garbage() {
        assert_eq!(peek_credential_sub("not-a-jwt"), None);
    }

    #[test]
    fn verify_rejects_wrong_typ() {
        let keypair = generate_dpop_keypair().unwrap();
        let claims = make_claims();

        let d_b64 = keypair.private_jwk["d"].as_str().unwrap();
        let d_bytes = URL_SAFE_NO_PAD.decode(d_b64).unwrap();
        let signing_key = p256::ecdsa::SigningKey::from_bytes((&d_bytes[..]).into()).unwrap();

        let header = serde_json::json!({ "alg": "ES256", "typ": "JWT" });
        let header_b64 = URL_SAFE_NO_PAD.encode(serde_json::to_vec(&header).unwrap());
        let payload_b64 = URL_SAFE_NO_PAD.encode(serde_json::to_vec(&claims).unwrap());
        let message = format!("{}.{}", header_b64, payload_b64);
        let sig: p256::ecdsa::Signature =
            p256::ecdsa::signature::Signer::sign(&signing_key, message.as_bytes());
        let token = format!(
            "{}.{}.{}",
            header_b64,
            payload_b64,
            URL_SAFE_NO_PAD.encode(sig.to_bytes())
        );

        let result = verify_credential(&token, &keypair.public_jwk);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("typ"));
    }
}
