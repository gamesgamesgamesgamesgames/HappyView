use base64::Engine;
use p256::pkcs8::EncodePrivateKey;
use sha2::{Digest, Sha256};

use crate::error::AppError;

use super::session::DpopJwk;

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

#[cfg(test)]
mod tests {
    use super::*;

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
