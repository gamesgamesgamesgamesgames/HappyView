use axum::extract::{FromRequest, Path, State};
use axum::http::StatusCode;
use axum::routing::{delete, post};
use axum::{Json, Router};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::AppState;
use crate::error::AppError;
use crate::event_log::{EventLog, Severity, log_event};

use super::client_auth;
use super::keys;
use super::sessions;

pub fn routes() -> Router<AppState> {
    Router::new()
        .route("/dpop-keys", post(provision_dpop_key))
        .route("/sessions", post(register_session))
        .route("/sessions/{did}", delete(delete_session))
}

// --- Request / response types ---

#[derive(Deserialize)]
struct ProvisionKeyBody {
    pkce_challenge: Option<String>,
}

#[derive(Serialize)]
struct ProvisionKeyResponse {
    provision_id: String,
    dpop_key: serde_json::Value,
}

#[derive(Deserialize)]
struct RegisterSessionBody {
    provision_id: String,
    pkce_verifier: Option<String>,
    did: String,
    access_token: String,
    refresh_token: Option<String>,
    expires_at: Option<String>,
    scopes: String,
    pds_url: Option<String>,
    issuer: Option<String>,
}

#[derive(Serialize)]
struct RegisterSessionResponse {
    session_id: String,
    did: String,
}

// --- Handlers ---

/// POST /oauth/dpop-keys — provision a new DPoP keypair.
///
/// Client credentials come from `X-Client-Key` and `X-Client-Secret` headers.
async fn provision_dpop_key(
    State(state): State<AppState>,
    req: axum::extract::Request,
) -> Result<(StatusCode, Json<ProvisionKeyResponse>), AppError> {
    let client_key = req
        .headers()
        .get("x-client-key")
        .and_then(|v| v.to_str().ok())
        .ok_or_else(|| AppError::Auth("X-Client-Key header required".into()))?
        .to_string();

    let client_secret = req
        .headers()
        .get("x-client-secret")
        .and_then(|v| v.to_str().ok())
        .map(|s| s.to_string());

    let origin = req
        .headers()
        .get("origin")
        .and_then(|v| v.to_str().ok())
        .map(|s| s.to_string());

    let body: ProvisionKeyBody = Json::<ProvisionKeyBody>::from_request(req, &state)
        .await
        .map_err(|e| AppError::BadRequest(format!("invalid request body: {e}")))?
        .0;

    let encryption_key = state
        .config
        .token_encryption_key
        .as_ref()
        .ok_or_else(|| AppError::Internal("TOKEN_ENCRYPTION_KEY not configured".into()))?;

    // Authenticate the client
    let client = if let Some(ref secret) = client_secret {
        client_auth::authenticate_confidential(&state.db, state.db_backend, &client_key, secret)
            .await?
    } else {
        // Public client — must provide PKCE challenge
        if body.pkce_challenge.is_none() {
            return Err(AppError::BadRequest(
                "public clients must provide pkce_challenge".into(),
            ));
        }
        client_auth::authenticate_public(
            &state.db,
            state.db_backend,
            &client_key,
            origin.as_deref(),
        )
        .await?
    };

    // Generate keypair
    let keypair = keys::generate_dpop_keypair()?;
    let id = Uuid::new_v4().to_string();
    let provision_id = format!("hvp_{}", hex::encode(rand::random::<[u8; 16]>()));

    // Store encrypted key
    keys::store_dpop_key(
        &state.db,
        state.db_backend,
        encryption_key,
        &id,
        &provision_id,
        &client.id,
        &keypair,
        body.pkce_challenge.as_deref(),
    )
    .await?;

    log_event(
        &state.db,
        EventLog {
            event_type: "dpop_key.provisioned".to_string(),
            severity: Severity::Info,
            actor_did: None,
            subject: Some(provision_id.clone()),
            detail: serde_json::json!({
                "client_key": client.client_key,
                "thumbprint": keypair.thumbprint,
            }),
        },
        state.db_backend,
    )
    .await;

    Ok((
        StatusCode::CREATED,
        Json(ProvisionKeyResponse {
            provision_id,
            dpop_key: keypair.private_jwk,
        }),
    ))
}

/// POST /oauth/sessions — register a token set after OAuth callback.
///
/// Client credentials come from `X-Client-Key` and `X-Client-Secret` headers.
async fn register_session(
    State(state): State<AppState>,
    req: axum::extract::Request,
) -> Result<(StatusCode, Json<RegisterSessionResponse>), AppError> {
    let client_key = req
        .headers()
        .get("x-client-key")
        .and_then(|v| v.to_str().ok())
        .ok_or_else(|| AppError::Auth("X-Client-Key header required".into()))?
        .to_string();

    let client_secret = req
        .headers()
        .get("x-client-secret")
        .and_then(|v| v.to_str().ok())
        .map(|s| s.to_string());

    let body: RegisterSessionBody = Json::<RegisterSessionBody>::from_request(req, &state)
        .await
        .map_err(|e| AppError::BadRequest(format!("invalid request body: {e}")))?
        .0;

    let encryption_key = state
        .config
        .token_encryption_key
        .as_ref()
        .ok_or_else(|| AppError::Internal("TOKEN_ENCRYPTION_KEY not configured".into()))?;

    // Look up the DPoP key by provision_id
    let (dpop_key_id, dpop_client_id, _private_jwk, _thumbprint, pkce_challenge) =
        keys::get_dpop_key(
            &state.db,
            state.db_backend,
            encryption_key,
            &body.provision_id,
        )
        .await?;

    // Authenticate the client and verify it matches the key's client
    let client = if let Some(ref secret) = client_secret {
        client_auth::authenticate_confidential(&state.db, state.db_backend, &client_key, secret)
            .await?
    } else {
        // Public client — verify PKCE
        let verifier = body.pkce_verifier.as_deref().ok_or_else(|| {
            AppError::BadRequest("public clients must provide pkce_verifier".into())
        })?;

        let challenge = pkce_challenge.as_deref().ok_or_else(|| {
            AppError::BadRequest("no PKCE challenge found for this provision".into())
        })?;

        if !client_auth::verify_pkce(challenge, verifier) {
            return Err(AppError::Auth("PKCE verification failed".into()));
        }

        client_auth::resolve_client_by_key(&state.db, state.db_backend, &client_key).await?
    };

    // Verify client_key matches the key's owning client
    if client.id != dpop_client_id {
        return Err(AppError::Auth(
            "provision_id does not belong to this client".into(),
        ));
    }

    // Validate scopes
    client_auth::validate_scopes(&body.scopes, &client.scopes, &state.lexicons).await?;

    // Clean up any existing session's DPoP key before upserting
    // (the ON CONFLICT upsert would orphan the old key otherwise)
    {
        let lookup_sql = crate::db::adapt_sql(
            "SELECT dpop_key_id FROM dpop_sessions WHERE api_client_id = ? AND user_did = ?",
            state.db_backend,
        );
        if let Ok(Some((old_key_id,))) = sqlx::query_as::<_, (String,)>(&lookup_sql)
            .bind(&client.id)
            .bind(&body.did)
            .fetch_optional(&state.db)
            .await
            && old_key_id != dpop_key_id
        {
            let del_sql =
                crate::db::adapt_sql("DELETE FROM dpop_keys WHERE id = ?", state.db_backend);
            let _ = sqlx::query(&del_sql)
                .bind(&old_key_id)
                .execute(&state.db)
                .await;
        }
    }

    // Store the session
    let session_id = Uuid::new_v4().to_string();
    sessions::store_dpop_session(
        &state.db,
        state.db_backend,
        encryption_key,
        &session_id,
        &client.id,
        &dpop_key_id,
        &body.did,
        &body.access_token,
        body.refresh_token.as_deref(),
        body.expires_at.as_deref(),
        &body.scopes,
        body.pds_url.as_deref(),
        body.issuer.as_deref(),
    )
    .await?;

    log_event(
        &state.db,
        EventLog {
            event_type: "dpop_session.created".to_string(),
            severity: Severity::Info,
            actor_did: Some(body.did.clone()),
            subject: Some(client.client_key.clone()),
            detail: serde_json::json!({
                "scopes": body.scopes,
            }),
        },
        state.db_backend,
    )
    .await;

    Ok((
        StatusCode::CREATED,
        Json(RegisterSessionResponse {
            session_id,
            did: body.did,
        }),
    ))
}

/// DELETE /oauth/sessions/:did — logout / revoke a session.
///
/// Confidential clients authenticate with `X-Client-Key` + `X-Client-Secret`.
/// Public clients authenticate with `X-Client-Key` + `Authorization: DPoP <token>` + `DPoP` proof.
async fn delete_session(
    State(state): State<AppState>,
    Path(did): Path<String>,
    req: axum::extract::Request,
) -> Result<StatusCode, AppError> {
    let client_key = req
        .headers()
        .get("x-client-key")
        .and_then(|v| v.to_str().ok())
        .ok_or_else(|| AppError::Auth("X-Client-Key header required".into()))?
        .to_string();

    let client_secret = req
        .headers()
        .get("x-client-secret")
        .and_then(|v| v.to_str().ok())
        .map(|s| s.to_string());

    let client = if let Some(ref secret) = client_secret {
        client_auth::authenticate_confidential(&state.db, state.db_backend, &client_key, secret)
            .await?
    } else {
        let resolved =
            client_auth::resolve_client_by_key(&state.db, state.db_backend, &client_key).await?;

        // Public clients must prove they hold the DPoP key + token
        if resolved.client_type == "public" {
            let auth_header = req
                .headers()
                .get("authorization")
                .and_then(|v| v.to_str().ok())
                .ok_or_else(|| {
                    AppError::Auth("public clients must provide Authorization: DPoP <token>".into())
                })?;
            let access_token = auth_header.strip_prefix("DPoP ").ok_or_else(|| {
                AppError::Auth("public clients must use DPoP authorization scheme".into())
            })?;
            let dpop_proof = req
                .headers()
                .get("dpop")
                .and_then(|v| v.to_str().ok())
                .ok_or_else(|| {
                    AppError::Auth("public clients must provide DPoP proof header".into())
                })?;

            let encryption_key =
                state.config.token_encryption_key.as_ref().ok_or_else(|| {
                    AppError::Internal("TOKEN_ENCRYPTION_KEY not configured".into())
                })?;

            // Look up the session to get the DPoP key thumbprint
            let session = sessions::get_dpop_session_by_token_hash(
                &state.db,
                state.db_backend,
                encryption_key,
                &resolved.id,
                access_token,
            )
            .await?;

            let thumbprint =
                keys::get_dpop_key_thumbprint(&state.db, state.db_backend, &session.dpop_key_id)
                    .await?;

            // Build request URL for htu validation
            let scheme = if state.config.public_url.starts_with("https") {
                "https"
            } else {
                "http"
            };
            let host = req
                .headers()
                .get("host")
                .and_then(|v| v.to_str().ok())
                .unwrap_or("localhost");
            let request_url = format!("{}://{}/oauth/sessions/{}", scheme, host, did);

            crate::oauth::dpop_proof::validate_dpop_proof(
                dpop_proof,
                "DELETE",
                &request_url,
                access_token,
                &thumbprint,
            )?;
        }

        resolved
    };

    sessions::delete_dpop_session(&state.db, state.db_backend, &client.id, &did).await?;

    log_event(
        &state.db,
        EventLog {
            event_type: "dpop_session.deleted".to_string(),
            severity: Severity::Info,
            actor_did: Some(did),
            subject: Some(client.client_key),
            detail: serde_json::json!({}),
        },
        state.db_backend,
    )
    .await;

    Ok(StatusCode::NO_CONTENT)
}
