//! Attestation signing for plugin records.
//!
//! Implements the ATProtocol attestation spec:
//! - Computes CID with $sig metadata for replay protection
//! - Signs using ECDSA (P-256 or K-256)
//! - Adds inline signatures to records

use cid::Cid;
use k256::ecdsa::{Signature, SigningKey, signature::Signer};
use serde_json::{Map, Value};
use sha2::{Digest, Sha256};
use std::sync::Arc;

// Multihash code for SHA2-256
const SHA2_256_CODE: u64 = 0x12;
// DAG-CBOR codec
const DAG_CBOR_CODEC: u64 = 0x71;

/// Attestation signer for HappyView
pub struct AttestationSigner {
    /// The signing key (K-256/secp256k1)
    signing_key: SigningKey,
    /// The key identifier (e.g., "did:web:happyview.example#attestation")
    key_id: String,
    /// The signature type identifier
    sig_type: String,
}

#[derive(Debug, thiserror::Error)]
pub enum AttestationError {
    #[error("Failed to encode record: {0}")]
    Encoding(String),
    #[error("Failed to sign: {0}")]
    Signing(String),
    #[error("Invalid key: {0}")]
    InvalidKey(String),
    #[error("Record missing required field: {0}")]
    MissingField(String),
}

impl AttestationSigner {
    /// Create a new signer from a hex-encoded private key
    pub fn from_hex(
        private_key_hex: &str,
        key_id: String,
        sig_type: String,
    ) -> Result<Self, AttestationError> {
        let key_bytes = hex::decode(private_key_hex)
            .map_err(|e| AttestationError::InvalidKey(format!("invalid hex: {}", e)))?;

        let signing_key = SigningKey::from_bytes((&key_bytes[..]).into())
            .map_err(|e| AttestationError::InvalidKey(format!("invalid key: {}", e)))?;

        Ok(Self {
            signing_key,
            key_id,
            sig_type,
        })
    }

    /// Create a new signer with a test key (for testing only)
    #[cfg(test)]
    pub fn for_testing(key_id: String, sig_type: String) -> Self {
        // Fixed test key (32 bytes of 0x01) - DO NOT USE IN PRODUCTION
        let test_key_bytes = [0x01u8; 32];
        let signing_key =
            SigningKey::from_bytes((&test_key_bytes[..]).into()).expect("valid test key");
        Self {
            signing_key,
            key_id,
            sig_type,
        }
    }

    /// Get the public key in compressed format (for verification)
    pub fn public_key_bytes(&self) -> Vec<u8> {
        use k256::ecdsa::VerifyingKey;
        let verifying_key = VerifyingKey::from(&self.signing_key);
        verifying_key.to_encoded_point(true).as_bytes().to_vec()
    }

    /// Sign a record and add the signature to the signatures array.
    ///
    /// # Arguments
    /// * `record` - The record to sign (will be modified to add signature)
    /// * `repository_did` - The DID of the repository (for replay protection)
    ///
    /// # Returns
    /// The CID of the signed content
    pub fn sign_record(
        &self,
        record: &mut Value,
        repository_did: &str,
    ) -> Result<Cid, AttestationError> {
        let obj = record
            .as_object_mut()
            .ok_or_else(|| AttestationError::Encoding("record must be an object".into()))?;

        // Remove existing signatures for CID computation
        let existing_signatures = obj.remove("signatures");

        // Inject $sig metadata for CID computation
        let sig_metadata = serde_json::json!({
            "$type": &self.sig_type,
            "repository": repository_did,
        });
        obj.insert("$sig".to_string(), sig_metadata);

        // Encode to CBOR (DAG-CBOR canonical form)
        let cbor_bytes = self.encode_dag_cbor(obj)?;

        // Compute CID (sha2-256, dag-cbor codec)
        let cid = self.compute_cid(&cbor_bytes);

        // Remove $sig (it's only for CID computation)
        obj.remove("$sig");

        // Sign the CID bytes
        let signature = self.sign_cid(&cid)?;

        // Create inline signature object
        let inline_sig = serde_json::json!({
            "$type": &self.sig_type,
            "key": &self.key_id,
            "signature": {
                "$bytes": base64::Engine::encode(&base64::engine::general_purpose::STANDARD, &signature)
            }
        });

        // Add to signatures array
        let signatures = obj
            .entry("signatures")
            .or_insert_with(|| Value::Array(vec![]));

        if let Value::Array(arr) = signatures {
            // Restore any existing signatures
            if let Some(Value::Array(existing)) = existing_signatures {
                for sig in existing {
                    arr.push(sig);
                }
            }
            arr.push(inline_sig);
        }

        Ok(cid)
    }

    /// Encode a JSON object to DAG-CBOR canonical form
    fn encode_dag_cbor(&self, obj: &Map<String, Value>) -> Result<Vec<u8>, AttestationError> {
        // Convert to ciborium Value and encode
        // DAG-CBOR requires deterministic key ordering (lexicographic)
        let cbor_value = json_to_cbor(&Value::Object(obj.clone()));

        let mut buf = Vec::new();
        ciborium::into_writer(&cbor_value, &mut buf)
            .map_err(|e| AttestationError::Encoding(format!("CBOR encoding failed: {}", e)))?;

        Ok(buf)
    }

    /// Compute CID from CBOR bytes (sha2-256, dag-cbor codec)
    fn compute_cid(&self, cbor_bytes: &[u8]) -> Cid {
        // SHA2-256 hash
        let digest = Sha256::digest(cbor_bytes);

        // Create multihash: varint(code) || varint(size) || digest
        let mut multihash_bytes = Vec::new();
        // SHA2-256 code (0x12)
        multihash_bytes.push(SHA2_256_CODE as u8);
        // Digest size (32 bytes)
        multihash_bytes.push(32u8);
        // The digest
        multihash_bytes.extend_from_slice(&digest);

        let multihash =
            cid::multihash::Multihash::<64>::from_bytes(&multihash_bytes).expect("valid multihash");

        // CID v1 with dag-cbor codec
        Cid::new_v1(DAG_CBOR_CODEC, multihash)
    }

    /// Sign a CID using ECDSA with low-S normalization
    fn sign_cid(&self, cid: &Cid) -> Result<Vec<u8>, AttestationError> {
        let cid_bytes = cid.to_bytes();

        // Sign using k256 ECDSA (automatically uses low-S)
        let signature: Signature = self.signing_key.sign(&cid_bytes);

        Ok(signature.to_bytes().to_vec())
    }
}

/// Convert JSON Value to ciborium Value with deterministic ordering
fn json_to_cbor(value: &Value) -> ciborium::Value {
    match value {
        Value::Null => ciborium::Value::Null,
        Value::Bool(b) => ciborium::Value::Bool(*b),
        Value::Number(n) => {
            if let Some(i) = n.as_i64() {
                ciborium::Value::Integer(i.into())
            } else if let Some(u) = n.as_u64() {
                ciborium::Value::Integer(u.into())
            } else if let Some(f) = n.as_f64() {
                ciborium::Value::Float(f)
            } else {
                ciborium::Value::Null
            }
        }
        Value::String(s) => {
            // Check for $bytes encoding (base64)
            ciborium::Value::Text(s.clone())
        }
        Value::Array(arr) => ciborium::Value::Array(arr.iter().map(json_to_cbor).collect()),
        Value::Object(obj) => {
            // Handle special $bytes encoding for binary data
            if obj.len() == 1
                && let Some(Value::String(b64)) = obj.get("$bytes")
                && let Ok(bytes) =
                    base64::Engine::decode(&base64::engine::general_purpose::STANDARD, b64)
            {
                return ciborium::Value::Bytes(bytes);
            }

            // Sort keys lexicographically for deterministic encoding
            let mut pairs: Vec<_> = obj
                .iter()
                .map(|(k, v)| (ciborium::Value::Text(k.clone()), json_to_cbor(v)))
                .collect();
            pairs.sort_by(|a, b| {
                if let (ciborium::Value::Text(ka), ciborium::Value::Text(kb)) = (&a.0, &b.0) {
                    ka.cmp(kb)
                } else {
                    std::cmp::Ordering::Equal
                }
            });

            ciborium::Value::Map(pairs)
        }
    }
}

/// Shared attestation signer for the application
pub type SharedAttestationSigner = Arc<AttestationSigner>;

/// Load attestation signer from environment variables
pub fn load_from_env() -> Result<Option<AttestationSigner>, AttestationError> {
    let private_key = match std::env::var("ATTESTATION_PRIVATE_KEY") {
        Ok(k) => k,
        Err(_) => return Ok(None), // No key configured, attestation disabled
    };

    let key_id = std::env::var("ATTESTATION_KEY_ID")
        .unwrap_or_else(|_| "did:web:localhost#attestation".to_string());

    let sig_type = std::env::var("ATTESTATION_SIG_TYPE")
        .unwrap_or_else(|_| "games.gamesgamesgamesgames.attestation".to_string());

    Ok(Some(AttestationSigner::from_hex(
        &private_key,
        key_id,
        sig_type,
    )?))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sign_record() {
        let signer = AttestationSigner::for_testing(
            "did:web:test.example#signing".to_string(),
            "test.signature".to_string(),
        );

        let mut record = serde_json::json!({
            "$type": "games.gamesgamesgamesgames.actor.game",
            "game": {"platform": "steam", "externalId": "440"},
            "platform": "steam",
            "createdAt": "2024-01-01T00:00:00Z"
        });

        let cid = signer
            .sign_record(&mut record, "did:plc:testuser")
            .expect("signing should succeed");

        // Verify signature was added
        let signatures = record["signatures"].as_array().expect("signatures array");
        assert_eq!(signatures.len(), 1);

        let sig = &signatures[0];
        assert_eq!(sig["$type"], "test.signature");
        assert_eq!(sig["key"], "did:web:test.example#signing");
        assert!(sig["signature"]["$bytes"].is_string());

        // CID should be valid
        assert!(!cid.to_bytes().is_empty());
    }

    #[test]
    fn test_deterministic_cid() {
        let signer = AttestationSigner::for_testing(
            "did:web:test.example#signing".to_string(),
            "test.signature".to_string(),
        );

        // Same record should produce same CID (before signature)
        let record1 = serde_json::json!({
            "a": 1,
            "b": 2,
            "c": {"nested": true}
        });

        let record2 = serde_json::json!({
            "c": {"nested": true},
            "a": 1,
            "b": 2
        });

        let mut r1 = record1.clone();
        let mut r2 = record2.clone();

        let cid1 = signer.sign_record(&mut r1, "did:plc:test").unwrap();
        let cid2 = signer.sign_record(&mut r2, "did:plc:test").unwrap();

        // Different signatures (random nonce in ECDSA) but...
        // Actually the CIDs should be the same since they're computed before signing
        // and the key ordering is normalized
        assert_eq!(cid1, cid2);
    }
}
