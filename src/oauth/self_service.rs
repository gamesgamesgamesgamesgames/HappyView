use axum::Json;
use axum::extract::State;
use axum::http::StatusCode;
use hex;
use rand::Rng;
use serde::Deserialize;
use sha2::{Digest, Sha256};
use uuid::Uuid;

use crate::AppState;
use crate::admin::types::CreateApiClientResponse;
use crate::db::{adapt_sql, now_rfc3339};
use crate::error::AppError;
use crate::event_log::{EventLog, Severity, log_event};

use super::client_auth;
use super::sessions;

#[derive(Deserialize)]
struct CreateChildApiClientBody {
    name: String,
    client_id_url: String,
    client_uri: String,
    redirect_uris: Vec<String>,
    #[serde(default = "default_scopes")]
    scopes: String,
    #[serde(default = "default_client_type")]
    client_type: String,
    allowed_origins: Option<Vec<String>>,
}

fn default_scopes() -> String {
    "atproto".to_string()
}

fn default_client_type() -> String {
    "confidential".to_string()
}

/// POST /oauth/api-clients — create a child API client (self-service).
///
/// Authenticated via DPoP (`Authorization: DPoP <token>` + `DPoP` proof + `X-Client-Key`).
/// Only top-level (admin-created) API clients can create children.
pub(super) async fn create_child_api_client(
    State(state): State<AppState>,
    req: axum::extract::Request,
) -> Result<(StatusCode, Json<CreateApiClientResponse>), AppError> {
    use axum::extract::FromRequest;

    let client_key_header = req
        .headers()
        .get("x-client-key")
        .and_then(|v| v.to_str().ok())
        .ok_or_else(|| AppError::Auth("Missing client identification".into()))?
        .to_string();

    let auth_header = req
        .headers()
        .get("authorization")
        .and_then(|v| v.to_str().ok())
        .ok_or_else(|| AppError::Auth("Authorization header required".into()))?
        .to_string();

    let access_token = auth_header
        .strip_prefix("DPoP ")
        .ok_or_else(|| AppError::Auth("DPoP authorization scheme required".into()))?;

    let dpop_proof = req
        .headers()
        .get("dpop")
        .and_then(|v| v.to_str().ok())
        .ok_or_else(|| AppError::Auth("DPoP proof header required".into()))?
        .to_string();

    let scheme = if state.config.public_url.starts_with("https") {
        "https"
    } else {
        "http"
    };
    let host = req
        .headers()
        .get("host")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("localhost")
        .to_string();
    let request_path = req
        .extensions()
        .get::<axum::extract::OriginalUri>()
        .map(|u| u.0.path().to_string())
        .unwrap_or_else(|| req.uri().path().to_string());

    let body: CreateChildApiClientBody =
        Json::<CreateChildApiClientBody>::from_request(req, &state)
            .await
            .map_err(|e| AppError::BadRequest(format!("invalid request body: {e}")))?
            .0;

    if body.client_type != "confidential" && body.client_type != "public" {
        return Err(AppError::BadRequest("Invalid client_type".into()));
    }

    let encryption_key = state
        .config
        .token_encryption_key
        .as_ref()
        .ok_or_else(|| AppError::Internal("TOKEN_ENCRYPTION_KEY not configured".into()))?;

    // Resolve the parent API client.
    let parent_client =
        client_auth::resolve_client_by_key(&state.db, state.db_backend, &client_key_header)
            .await
            .map_err(|_| AppError::Auth("Invalid client".into()))?;

    // Verify the client is a top-level client (no parent) and fetch its creator.
    let parent_check_sql = adapt_sql(
        "SELECT parent_client_id, created_by FROM api_clients WHERE id = ?",
        state.db_backend,
    );
    let parent_row: Option<(Option<String>, String)> = sqlx::query_as(&parent_check_sql)
        .bind(&parent_client.id)
        .fetch_optional(&state.db)
        .await
        .map_err(|e| AppError::Internal(format!("failed to check parent status: {e}")))?;

    let parent_created_by = match parent_row {
        Some((Some(_), _)) => {
            return Err(AppError::Forbidden(
                "Child clients cannot create API clients".into(),
            ));
        }
        Some((None, created_by)) => created_by,
        None => return Err(AppError::Auth("Invalid client".into())),
    };

    // Validate the DPoP proof and resolve the authenticated user.
    let session = sessions::get_dpop_session_by_token_hash(
        &state.db,
        state.db_backend,
        encryption_key,
        &parent_client.id,
        access_token,
    )
    .await?;

    if let Some(ref expires_at) = session.token_expires_at
        && let Ok(exp) = chrono::DateTime::parse_from_rfc3339(expires_at)
        && exp < chrono::Utc::now()
    {
        return Err(AppError::Auth("token_expired".into()));
    }

    let thumbprint =
        super::keys::get_dpop_key_thumbprint(&state.db, state.db_backend, &session.dpop_key_id)
            .await?;

    let request_url = format!("{}://{}{}", scheme, host, request_path);
    super::dpop_proof::validate_dpop_proof(
        &dpop_proof,
        "POST",
        &request_url,
        access_token,
        &thumbprint,
    )?;

    let user_did = &session.user_did;

    // Verify the parent client's owner exists in the users table.
    let user_check_sql = adapt_sql("SELECT id FROM users WHERE did = ?", state.db_backend);
    let user_exists: Option<(String,)> = sqlx::query_as(&user_check_sql)
        .bind(&parent_created_by)
        .fetch_optional(&state.db)
        .await
        .map_err(|e| AppError::Internal(format!("failed to check user: {e}")))?;

    if user_exists.is_none() {
        return Err(AppError::Forbidden("Parent client owner not found".into()));
    }

    // Check for duplicate client_id_url.
    let dup_check_sql = adapt_sql(
        "SELECT id FROM api_clients WHERE client_id_url = ?",
        state.db_backend,
    );
    let dup: Option<(String,)> = sqlx::query_as(&dup_check_sql)
        .bind(&body.client_id_url)
        .fetch_optional(&state.db)
        .await
        .map_err(|e| AppError::Internal(format!("failed to check client_id_url: {e}")))?;

    if dup.is_some() {
        return Err(AppError::Conflict(
            "client_id_url already registered".into(),
        ));
    }

    // Generate the client key and secret.
    let mut random_bytes = [0u8; 16];
    rand::rng().fill(&mut random_bytes);
    let child_client_key = format!("hvc_{}", hex::encode(random_bytes));

    let (client_secret, client_secret_hash) = if body.client_type == "confidential" {
        let mut secret_bytes = [0u8; 32];
        rand::rng().fill(&mut secret_bytes);
        let secret = format!("hvs_{}", hex::encode(secret_bytes));
        let hash = hex::encode(Sha256::digest(secret.as_bytes()));
        (Some(secret), hash)
    } else {
        (None, String::new())
    };

    let id = Uuid::new_v4().to_string();
    let now = now_rfc3339();
    let redirect_uris_json =
        serde_json::to_string(&body.redirect_uris).unwrap_or_else(|_| "[]".to_string());
    let allowed_origins_json = body
        .allowed_origins
        .as_ref()
        .map(|origins| serde_json::to_string(origins).unwrap_or_else(|_| "[]".to_string()));

    let insert_sql = adapt_sql(
        "INSERT INTO api_clients (id, client_key, client_secret_hash, name, client_id_url, client_uri, redirect_uris, scopes, rate_limit_capacity, rate_limit_refill_rate, client_type, allowed_origins, is_active, created_by, created_at, updated_at, parent_client_id, owner_did) VALUES (?, ?, ?, ?, ?, ?, ?, ?, NULL, NULL, ?, ?, 1, ?, ?, ?, ?, ?)",
        state.db_backend,
    );

    sqlx::query(&insert_sql)
        .bind(&id)
        .bind(&child_client_key)
        .bind(&client_secret_hash)
        .bind(&body.name)
        .bind(&body.client_id_url)
        .bind(&body.client_uri)
        .bind(&redirect_uris_json)
        .bind(&body.scopes)
        .bind(&body.client_type)
        .bind(&allowed_origins_json)
        .bind(user_did)
        .bind(&now)
        .bind(&now)
        .bind(&parent_client.id)
        .bind(user_did)
        .execute(&state.db)
        .await
        .map_err(|e| AppError::Internal(format!("failed to create child api client: {e}")))?;

    // Register the new client in the OAuth registry.
    let oauth_params = crate::auth::client_registry::ApiClientOAuthParams {
        plc_url: state.config.plc_url.clone(),
        state_store: state.oauth_state_store.clone(),
        session_store_pool: state.db.clone(),
        db_backend: state.db_backend,
    };
    if let Err(e) = state.oauth.register_api_client(
        &body.client_id_url,
        &body.client_uri,
        body.redirect_uris.clone(),
        &body.scopes,
        &oauth_params,
    ) {
        tracing::warn!(client_id = %body.client_id_url, error = %e, "OAuth client registration failed (DB row created)");
    }

    // Register the client identity for request validation.
    state.rate_limiter.register_client_identity(
        child_client_key.clone(),
        crate::rate_limit::ClientIdentity {
            secret_hash: client_secret_hash.clone(),
            client_uri: body.client_uri.clone(),
        },
    );

    // Register the child with its own rate limit bucket using instance defaults.
    let defaults = state.rate_limiter.defaults();
    state.rate_limiter.register_client_config(
        child_client_key.clone(),
        crate::rate_limit::RateLimitConfig {
            capacity: state.config.default_rate_limit_capacity,
            refill_rate: state.config.default_rate_limit_refill_rate,
            default_query_cost: defaults.query_cost,
            default_procedure_cost: defaults.procedure_cost,
            default_proxy_cost: defaults.proxy_cost,
        },
    );

    log_event(
        &state.db,
        EventLog {
            event_type: "api_client.created".to_string(),
            severity: Severity::Info,
            actor_did: Some(user_did.clone()),
            subject: Some(body.name.clone()),
            detail: serde_json::json!({
                "client_key": child_client_key,
                "client_id_url": body.client_id_url,
                "parent_client_id": parent_client.id,
                "self_service": true,
            }),
        },
        state.db_backend,
    )
    .await;

    Ok((
        StatusCode::CREATED,
        Json(CreateApiClientResponse {
            id,
            client_key: child_client_key,
            client_secret,
            name: body.name,
            client_id_url: body.client_id_url,
            client_type: body.client_type,
        }),
    ))
}
