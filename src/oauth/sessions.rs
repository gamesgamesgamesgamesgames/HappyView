use sha2::{Digest, Sha256};

use crate::db::{DatabaseBackend, adapt_sql, now_rfc3339};
use crate::error::AppError;
use crate::plugin::encryption::{decrypt, encrypt};

/// Compute a hex-encoded SHA-256 hash of a token for indexed lookup.
fn token_hash(token: &str) -> String {
    hex::encode(Sha256::digest(token.as_bytes()))
}

/// Stored DPoP session data (decrypted).
pub struct DpopSession {
    pub id: String,
    pub api_client_id: String,
    pub dpop_key_id: String,
    pub user_did: String,
    pub access_token: String,
    pub refresh_token: Option<String>,
    pub token_expires_at: Option<String>,
    pub scopes: String,
    pub pds_url: Option<String>,
    pub issuer: Option<String>,
}

/// Store or update a DPoP session.
///
/// Uses ON CONFLICT to upsert — if a session already exists for this
/// (api_client_id, user_did), it updates the token data.
#[allow(clippy::too_many_arguments)]
pub async fn store_dpop_session(
    pool: &sqlx::AnyPool,
    backend: DatabaseBackend,
    encryption_key: &[u8; 32],
    id: &str,
    api_client_id: &str,
    dpop_key_id: &str,
    user_did: &str,
    access_token: &str,
    refresh_token: Option<&str>,
    token_expires_at: Option<&str>,
    scopes: &str,
    pds_url: Option<&str>,
    issuer: Option<&str>,
) -> Result<(), AppError> {
    let access_enc = encrypt(encryption_key, access_token.as_bytes())
        .map_err(|e| AppError::Internal(format!("failed to encrypt access token: {e}")))?;

    let access_hash = token_hash(access_token);

    let refresh_enc = refresh_token
        .map(|t| {
            encrypt(encryption_key, t.as_bytes())
                .map_err(|e| AppError::Internal(format!("failed to encrypt refresh token: {e}")))
        })
        .transpose()?;

    let now = now_rfc3339();
    let sql = adapt_sql(
        r#"INSERT INTO dpop_sessions (id, api_client_id, dpop_key_id, user_did, access_token_enc, access_token_hash, refresh_token_enc, token_expires_at, scopes, pds_url, issuer, created_at, updated_at)
           VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
           ON CONFLICT (api_client_id, user_did) DO UPDATE SET
               dpop_key_id = EXCLUDED.dpop_key_id,
               access_token_enc = EXCLUDED.access_token_enc,
               access_token_hash = EXCLUDED.access_token_hash,
               refresh_token_enc = EXCLUDED.refresh_token_enc,
               token_expires_at = EXCLUDED.token_expires_at,
               scopes = EXCLUDED.scopes,
               pds_url = EXCLUDED.pds_url,
               issuer = EXCLUDED.issuer,
               updated_at = EXCLUDED.updated_at"#,
        backend,
    );

    sqlx::query(&sql)
        .bind(id)
        .bind(api_client_id)
        .bind(dpop_key_id)
        .bind(user_did)
        .bind(&access_enc)
        .bind(&access_hash)
        .bind(&refresh_enc)
        .bind(token_expires_at)
        .bind(scopes)
        .bind(pds_url)
        .bind(issuer)
        .bind(&now)
        .bind(&now)
        .execute(pool)
        .await
        .map_err(|e| AppError::Internal(format!("failed to store DPoP session: {e}")))?;

    Ok(())
}

/// Look up a DPoP session by api_client_id and user_did, decrypting tokens.
pub async fn get_dpop_session(
    pool: &sqlx::AnyPool,
    backend: DatabaseBackend,
    encryption_key: &[u8; 32],
    api_client_id: &str,
    user_did: &str,
) -> Result<DpopSession, AppError> {
    let sql = adapt_sql(
        "SELECT id, dpop_key_id, access_token_enc, refresh_token_enc, token_expires_at, scopes, pds_url, issuer FROM dpop_sessions WHERE api_client_id = ? AND user_did = ?",
        backend,
    );

    #[allow(clippy::type_complexity)]
    let row: Option<(
        String,
        String,
        Vec<u8>,
        Option<Vec<u8>>,
        Option<String>,
        String,
        Option<String>,
        Option<String>,
    )> = sqlx::query_as(&sql)
        .bind(api_client_id)
        .bind(user_did)
        .fetch_optional(pool)
        .await
        .map_err(|e| AppError::Internal(format!("failed to look up DPoP session: {e}")))?;

    let (id, dpop_key_id, access_enc, refresh_enc, token_expires_at, scopes, pds_url, issuer) =
        row.ok_or_else(|| AppError::NotFound("DPoP session not found".into()))?;

    let access_token = String::from_utf8(
        decrypt(encryption_key, &access_enc)
            .map_err(|e| AppError::Internal(format!("failed to decrypt access token: {e}")))?,
    )
    .map_err(|e| AppError::Internal(format!("invalid access token bytes: {e}")))?;

    let refresh_token = refresh_enc
        .map(|enc| {
            let bytes = decrypt(encryption_key, &enc)
                .map_err(|e| AppError::Internal(format!("failed to decrypt refresh token: {e}")))?;
            String::from_utf8(bytes)
                .map_err(|e| AppError::Internal(format!("invalid refresh token bytes: {e}")))
        })
        .transpose()?;

    Ok(DpopSession {
        id,
        api_client_id: api_client_id.to_string(),
        dpop_key_id,
        user_did: user_did.to_string(),
        access_token,
        refresh_token,
        token_expires_at,
        scopes,
        pds_url,
        issuer,
    })
}

/// Look up a DPoP session by api_client_id and access token.
/// Uses the `access_token_hash` column for indexed lookup instead of
/// decrypting every session.
pub async fn get_dpop_session_by_token_hash(
    pool: &sqlx::AnyPool,
    backend: DatabaseBackend,
    encryption_key: &[u8; 32],
    api_client_id: &str,
    access_token: &str,
) -> Result<DpopSession, AppError> {
    let hash = token_hash(access_token);
    let sql = adapt_sql(
        "SELECT id, dpop_key_id, user_did, access_token_enc, refresh_token_enc, token_expires_at, scopes, pds_url, issuer FROM dpop_sessions WHERE api_client_id = ? AND access_token_hash = ?",
        backend,
    );

    #[allow(clippy::type_complexity)]
    let row: Option<(
        String,
        String,
        String,
        Vec<u8>,
        Option<Vec<u8>>,
        Option<String>,
        String,
        Option<String>,
        Option<String>,
    )> = sqlx::query_as(&sql)
        .bind(api_client_id)
        .bind(&hash)
        .fetch_optional(pool)
        .await
        .map_err(|e| AppError::Internal(format!("failed to look up DPoP session: {e}")))?;

    let (
        id,
        dpop_key_id,
        user_did,
        access_enc,
        refresh_enc,
        token_expires_at,
        scopes,
        pds_url,
        issuer,
    ) = row.ok_or_else(|| AppError::Auth("no matching DPoP session".into()))?;

    let access_token_dec = String::from_utf8(
        decrypt(encryption_key, &access_enc)
            .map_err(|e| AppError::Internal(format!("failed to decrypt access token: {e}")))?,
    )
    .map_err(|e| AppError::Internal(format!("invalid access token bytes: {e}")))?;

    let refresh_token = refresh_enc
        .map(|enc| {
            let bytes = decrypt(encryption_key, &enc)
                .map_err(|e| AppError::Internal(format!("failed to decrypt refresh token: {e}")))?;
            String::from_utf8(bytes)
                .map_err(|e| AppError::Internal(format!("invalid refresh token bytes: {e}")))
        })
        .transpose()?;

    Ok(DpopSession {
        id,
        api_client_id: api_client_id.to_string(),
        dpop_key_id,
        user_did,
        access_token: access_token_dec,
        refresh_token,
        token_expires_at,
        scopes,
        pds_url,
        issuer,
    })
}

/// Delete a DPoP session by api_client_id and user_did.
pub async fn delete_dpop_session(
    pool: &sqlx::AnyPool,
    backend: DatabaseBackend,
    api_client_id: &str,
    user_did: &str,
) -> Result<String, AppError> {
    // Look up the dpop_key_id before deleting so we can clean up the key too
    let lookup_sql = adapt_sql(
        "SELECT dpop_key_id FROM dpop_sessions WHERE api_client_id = ? AND user_did = ?",
        backend,
    );

    let row: Option<(String,)> = sqlx::query_as(&lookup_sql)
        .bind(api_client_id)
        .bind(user_did)
        .fetch_optional(pool)
        .await
        .map_err(|e| AppError::Internal(format!("failed to look up DPoP session: {e}")))?;

    let (dpop_key_id,) = row.ok_or_else(|| AppError::NotFound("DPoP session not found".into()))?;

    let del_session_sql = adapt_sql(
        "DELETE FROM dpop_sessions WHERE api_client_id = ? AND user_did = ?",
        backend,
    );
    sqlx::query(&del_session_sql)
        .bind(api_client_id)
        .bind(user_did)
        .execute(pool)
        .await
        .map_err(|e| AppError::Internal(format!("failed to delete DPoP session: {e}")))?;

    let del_key_sql = adapt_sql("DELETE FROM dpop_keys WHERE id = ?", backend);
    sqlx::query(&del_key_sql)
        .bind(&dpop_key_id)
        .execute(pool)
        .await
        .map_err(|e| AppError::Internal(format!("failed to delete DPoP key: {e}")))?;

    Ok(dpop_key_id)
}
