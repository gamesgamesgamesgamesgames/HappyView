use crate::AppState;
use crate::auth::COOKIE_NAME;
use crate::db::{adapt_sql, now_rfc3339};
use crate::error::AppError;
use atrium_oauth::{AuthorizeOptions, KnownScope, Scope};
use axum::{
    Json, Router,
    extract::{Query, State},
    response::Redirect,
    routing::{get, post},
};
use axum_extra::extract::cookie::{Cookie, Key, SignedCookieJar};
use serde::Deserialize;

/// Legacy cookie name from the old cookie-based redirect approach.
/// Detected and removed in the callback to clean up stale cookies.
const LEGACY_REDIRECT_COOKIE: &str = "happyview_redirect";

#[derive(Deserialize)]
pub struct LoginQuery {
    handle: String,
    redirect_uri: Option<String>,
}

/// Parse a whitespace-separated OAuth scope string into typed `Scope` values.
/// Known ATProto scope names are mapped to `Scope::Known`; anything else
/// (e.g. `include:*` permission set references) becomes `Scope::Unknown`.
pub fn parse_scope_string(scope_str: &str) -> Vec<Scope> {
    scope_str
        .split_whitespace()
        .map(|s| match s {
            "atproto" => Scope::Known(KnownScope::Atproto),
            "transition:generic" => Scope::Known(KnownScope::TransitionGeneric),
            "transition:chat.bsky" => Scope::Known(KnownScope::TransitionChatBsky),
            other => Scope::Unknown(other.to_string()),
        })
        .collect()
}

#[derive(Deserialize)]
pub struct CallbackQuery {
    code: String,
    state: Option<String>,
    iss: Option<String>,
}

pub fn routes() -> Router<AppState> {
    Router::new()
        .route("/login", get(login))
        .route("/callback", get(callback))
        .route("/logout", post(logout))
        .route("/me", get(me))
}

async fn login(
    State(state): State<AppState>,
    jar: SignedCookieJar<Key>,
    Query(query): Query<LoginQuery>,
) -> Result<(SignedCookieJar<Key>, Json<serde_json::Value>), AppError> {
    tracing::debug!(handle = %query.handle, redirect_uri = ?query.redirect_uri, "login request");

    // Read the configured scopes from the settings DB. Falls back to `atproto`
    // only if unset — that matches what we serve from `/oauth/client-metadata.json`.
    let scopes = match crate::admin::settings::get_setting(
        &state.db,
        "oauth_scopes",
        state.db_backend,
    )
    .await
    {
        Some(s) => {
            let parsed = parse_scope_string(&s);
            if parsed.is_empty() {
                vec![Scope::Known(KnownScope::Atproto)]
            } else {
                parsed
            }
        }
        None => vec![Scope::Known(KnownScope::Atproto)],
    };

    tracing::debug!(scopes = ?scopes, "resolved oauth scopes");

    // Hold the authorize lock so that authorize() + take_last_state_key() are atomic.
    // This prevents concurrent logins from swapping each other's state keys.
    let _authorize_guard = state.oauth_state_store.authorize_lock.lock().await;

    let options = AuthorizeOptions {
        scopes,
        ..Default::default()
    };

    let url = state
        .oauth
        .authorize(&query.handle, options)
        .await
        .map_err(|e| AppError::Internal(format!("OAuth authorize failed: {e}")))?;

    // Capture the state key immediately after authorize(). We can't parse it from the URL
    // because atrium uses PAR (Pushed Authorization Requests), so the state is embedded
    // in the pushed request, not visible in the URL.
    let oauth_state = state.oauth_state_store.take_last_state_key();

    drop(_authorize_guard);

    tracing::debug!(authorize_url = %url, "authorize URL generated");

    // Store the redirect URI in the database, keyed by the OAuth state parameter.
    // This avoids third-party cookie issues when Pentaract (cross-origin) calls this endpoint.
    if let Some(redirect_uri) = &query.redirect_uri {
        tracing::debug!(oauth_state = ?oauth_state, redirect_uri = %redirect_uri, "storing redirect for state");

        if let Some(oauth_state) = oauth_state {
            let now = now_rfc3339();
            let expires_at = (chrono::Utc::now() + chrono::Duration::minutes(10)).to_rfc3339();
            let sql = adapt_sql(
                "INSERT INTO auth_login_redirects (state, redirect_uri, created_at, expires_at) VALUES (?, ?, ?, ?)",
                state.db_backend,
            );
            let _ = sqlx::query(&sql)
                .bind(&oauth_state)
                .bind(redirect_uri)
                .bind(&now)
                .bind(&expires_at)
                .execute(&state.db)
                .await;
        } else {
            tracing::warn!("no state key captured from OAuth authorize — redirect will be lost");
        }
    }

    Ok((jar, Json(serde_json::json!({ "url": url }))))
}

async fn callback(
    State(state): State<AppState>,
    jar: SignedCookieJar<Key>,
    Query(query): Query<CallbackQuery>,
) -> Result<(SignedCookieJar<Key>, Redirect), AppError> {
    tracing::debug!(state = ?query.state, "callback received");

    // Look up the redirect URI from the database before the OAuth library consumes the state
    let redirect_url = if let Some(oauth_state) = &query.state {
        let sql = adapt_sql(
            "SELECT redirect_uri FROM auth_login_redirects WHERE state = ? AND expires_at > ?",
            state.db_backend,
        );
        let now = now_rfc3339();
        let row: Option<(String,)> = sqlx::query_as(&sql)
            .bind(oauth_state)
            .bind(&now)
            .fetch_optional(&state.db)
            .await
            .unwrap_or(None);

        // Clean up the row (one-time use)
        if row.is_some() {
            let delete_sql = adapt_sql(
                "DELETE FROM auth_login_redirects WHERE state = ?",
                state.db_backend,
            );
            let _ = sqlx::query(&delete_sql)
                .bind(oauth_state)
                .execute(&state.db)
                .await;
        }

        tracing::debug!(found_redirect = ?row, "redirect lookup result");
        row.map(|(uri,)| uri)
    } else {
        tracing::debug!("no state in callback query");
        None
    };

    let params = atrium_oauth::CallbackParams {
        code: query.code,
        state: query.state,
        iss: query.iss,
    };

    let (session, _app_state) = state
        .oauth
        .callback(params)
        .await
        .map_err(|e| AppError::Internal(format!("OAuth callback failed: {e}")))?;

    use atrium_api::agent::SessionManager;
    let did = session
        .did()
        .await
        .ok_or_else(|| AppError::Internal("no DID in OAuth session".into()))?;

    // Use DB-stored redirect, or default to "/"
    let redirect_url = redirect_url.unwrap_or_else(|| "/".to_string());
    tracing::debug!(redirect_url = %redirect_url, "redirecting after callback");

    // Set the session cookie
    // Must use SameSite=None for cross-origin requests (e.g., Pentaract calling HappyView)
    let mut session_cookie = Cookie::new(COOKIE_NAME, did.to_string());
    session_cookie.set_path("/");
    session_cookie.set_http_only(true);
    session_cookie.set_same_site(axum_extra::extract::cookie::SameSite::None);
    session_cookie.set_secure(true); // Required when SameSite=None

    // Remove the legacy redirect cookie if present (old cookie-based approach)
    let jar = if jar.get(LEGACY_REDIRECT_COOKIE).is_some() {
        let mut removal = Cookie::from(LEGACY_REDIRECT_COOKIE);
        removal.set_path("/");
        removal.set_same_site(axum_extra::extract::cookie::SameSite::None);
        removal.set_secure(true);
        jar.add(session_cookie).remove(removal)
    } else {
        jar.add(session_cookie)
    };

    Ok((jar, Redirect::to(&redirect_url)))
}

async fn logout(
    State(state): State<AppState>,
    jar: SignedCookieJar<Key>,
) -> Result<SignedCookieJar<Key>, AppError> {
    if let Some(cookie) = jar.get(COOKIE_NAME) {
        let did_str = cookie.value().to_string();
        if let Ok(did) = atrium_api::types::string::Did::new(did_str) {
            let _ = state.oauth.revoke(&did).await;
        }
    }

    let mut removal = Cookie::from(COOKIE_NAME);
    removal.set_path("/");
    removal.set_same_site(axum_extra::extract::cookie::SameSite::None);
    removal.set_secure(true);
    let jar = jar.remove(removal);
    Ok(jar)
}

#[derive(serde::Serialize)]
struct MeResponse {
    did: String,
    is_admin: bool,
}

async fn me(
    State(state): State<AppState>,
    jar: SignedCookieJar<Key>,
) -> Result<Json<MeResponse>, AppError> {
    let cookie = jar
        .get(COOKIE_NAME)
        .ok_or(AppError::Auth("not authenticated".into()))?;
    let did = cookie.value().to_string();

    let backend = state.db_backend;
    let user: Option<(i32,)> =
        sqlx::query_as(&adapt_sql("SELECT 1 FROM users WHERE did = ?", backend))
            .bind(&did)
            .fetch_optional(&state.db)
            .await
            .map_err(|e| AppError::Internal(format!("user lookup failed: {e}")))?;

    Ok(Json(MeResponse {
        did,
        is_admin: user.is_some(),
    }))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_scope_string_maps_known_scopes() {
        let scopes = parse_scope_string("atproto transition:generic transition:chat.bsky");
        assert_eq!(scopes.len(), 3);
        assert!(matches!(scopes[0], Scope::Known(KnownScope::Atproto)));
        assert!(matches!(
            scopes[1],
            Scope::Known(KnownScope::TransitionGeneric)
        ));
        assert!(matches!(
            scopes[2],
            Scope::Known(KnownScope::TransitionChatBsky)
        ));
    }

    #[test]
    fn parse_scope_string_treats_unknown_as_unknown() {
        let scopes = parse_scope_string("atproto include:games.gamesgamesgamesgames.authBasic");
        assert_eq!(scopes.len(), 2);
        assert!(matches!(scopes[0], Scope::Known(KnownScope::Atproto)));
        match &scopes[1] {
            Scope::Unknown(s) => {
                assert_eq!(s, "include:games.gamesgamesgamesgames.authBasic");
            }
            _ => panic!("expected Scope::Unknown for include: reference"),
        }
    }

    #[test]
    fn parse_scope_string_handles_extra_whitespace_and_empty_input() {
        let scopes = parse_scope_string("   atproto   \n\t  transition:generic  ");
        assert_eq!(scopes.len(), 2);
        assert!(matches!(scopes[0], Scope::Known(KnownScope::Atproto)));
        assert!(matches!(
            scopes[1],
            Scope::Known(KnownScope::TransitionGeneric)
        ));

        let empty = parse_scope_string("   \n  \t  ");
        assert!(empty.is_empty());
    }
}
