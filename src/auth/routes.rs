use axum::{
    Json, Router,
    extract::{Query, State},
    response::Redirect,
    routing::{get, post},
};
use axum_extra::extract::cookie::{Cookie, Key, SignedCookieJar};
use serde::Deserialize;

use crate::AppState;
use crate::auth::COOKIE_NAME;
use crate::db::adapt_sql;
use crate::error::AppError;

const REDIRECT_COOKIE_NAME: &str = "happyview_redirect";

#[derive(Deserialize)]
pub struct LoginQuery {
    handle: String,
    redirect_uri: Option<String>,
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
    let url = state
        .oauth
        .authorize(&query.handle, Default::default())
        .await
        .map_err(|e| AppError::Internal(format!("OAuth authorize failed: {e}")))?;

    // Store the redirect URI in a cookie if provided
    // Must use SameSite=None for cross-origin requests (e.g., Pentaract calling HappyView)
    let jar = if let Some(redirect_uri) = query.redirect_uri {
        let mut cookie = Cookie::new(REDIRECT_COOKIE_NAME, redirect_uri);
        cookie.set_path("/");
        cookie.set_http_only(true);
        cookie.set_same_site(axum_extra::extract::cookie::SameSite::None);
        cookie.set_secure(true); // Required when SameSite=None
        jar.add(cookie)
    } else {
        jar
    };

    Ok((jar, Json(serde_json::json!({ "url": url }))))
}

async fn callback(
    State(state): State<AppState>,
    jar: SignedCookieJar<Key>,
    Query(query): Query<CallbackQuery>,
) -> Result<(SignedCookieJar<Key>, Redirect), AppError> {
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

    // Get the redirect URL from cookie, defaulting to "/"
    let redirect_url = jar
        .get(REDIRECT_COOKIE_NAME)
        .map(|c| c.value().to_string())
        .unwrap_or_else(|| "/".to_string());

    // Set the session cookie
    // Must use SameSite=None for cross-origin requests (e.g., Pentaract calling HappyView)
    let mut session_cookie = Cookie::new(COOKIE_NAME, did.to_string());
    session_cookie.set_path("/");
    session_cookie.set_http_only(true);
    session_cookie.set_same_site(axum_extra::extract::cookie::SameSite::None);
    session_cookie.set_secure(true); // Required when SameSite=None

    // Remove the redirect cookie (must match attributes from login)
    let mut redirect_removal = Cookie::from(REDIRECT_COOKIE_NAME);
    redirect_removal.set_path("/");
    redirect_removal.set_same_site(axum_extra::extract::cookie::SameSite::None);
    redirect_removal.set_secure(true);

    let jar = jar.add(session_cookie).remove(redirect_removal);
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
