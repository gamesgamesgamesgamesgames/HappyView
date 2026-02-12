use axum::extract::FromRequestParts;
use axum::http::request::Parts;
use jsonwebtoken::{decode, Algorithm, DecodingKey, Validation};
use serde::{Deserialize, Serialize};

use crate::auth::jwks::JwksProvider;
use crate::error::AppError;

/// JWT claims from an AIP-issued access token.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Claims {
    pub iss: String,
    pub sub: String,
    pub aud: serde_json::Value,
    pub exp: u64,
    pub iat: u64,
    #[serde(default)]
    pub scope: Option<String>,
}

impl Claims {
    /// The authenticated user's DID (the `sub` claim).
    pub fn did(&self) -> &str {
        &self.sub
    }
}

/// Axum extractor that validates the Bearer token against AIP's JWKS.
///
/// Use in handler signatures:
/// ```ignore
/// async fn my_handler(claims: Claims) -> impl IntoResponse { ... }
/// ```
impl<S> FromRequestParts<S> for Claims
where
    S: Send + Sync,
    JwksProvider: FromRef<S>,
{
    type Rejection = AppError;

    async fn from_request_parts(parts: &mut Parts, state: &S) -> Result<Self, Self::Rejection> {
        let provider = JwksProvider::from_ref(state);

        let header = parts
            .headers
            .get("authorization")
            .and_then(|v| v.to_str().ok())
            .ok_or_else(|| AppError::Auth("missing Authorization header".into()))?;

        let token = header
            .strip_prefix("Bearer ")
            .or_else(|| header.strip_prefix("DPoP "))
            .ok_or_else(|| AppError::Auth("invalid Authorization scheme".into()))?;

        let jwks = provider
            .keyset()
            .await
            .ok_or_else(|| AppError::Auth("JWKS not yet available".into()))?;

        // Decode the JWT header to find the `kid`.
        let jwt_header = jsonwebtoken::decode_header(token)
            .map_err(|e| AppError::Auth(format!("invalid token header: {e}")))?;

        let kid = jwt_header
            .kid
            .as_deref()
            .ok_or_else(|| AppError::Auth("token missing kid".into()))?;

        let jwk = jwks
            .find(kid)
            .ok_or_else(|| AppError::Auth("unknown signing key".into()))?;

        let key = DecodingKey::from_jwk(jwk)
            .map_err(|e| AppError::Auth(format!("bad JWK: {e}")))?;

        let mut validation = Validation::new(Algorithm::ES256);
        validation.validate_aud = false; // AIP sets aud to the client_id; we skip it here

        let data = decode::<Claims>(token, &key, &validation)
            .map_err(|e| AppError::Auth(format!("token validation failed: {e}")))?;

        Ok(data.claims)
    }
}

/// Helper trait so we can pull JwksProvider out of app state.
pub trait FromRef<T> {
    fn from_ref(input: &T) -> Self;
}

impl FromRef<crate::AppState> for JwksProvider {
    fn from_ref(state: &crate::AppState) -> Self {
        state.jwks.clone()
    }
}
