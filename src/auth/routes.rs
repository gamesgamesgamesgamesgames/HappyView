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

#[derive(Deserialize)]
pub struct LoginQuery {
    handle: String,
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
    Query(query): Query<LoginQuery>,
) -> Result<Json<serde_json::Value>, AppError> {
    let url = state
        .oauth
        .authorize(&query.handle, Default::default())
        .await
        .map_err(|e| AppError::Internal(format!("OAuth authorize failed: {e}")))?;

    Ok(Json(serde_json::json!({ "url": url })))
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

    let mut cookie = Cookie::new(COOKIE_NAME, did.to_string());
    cookie.set_path("/");
    cookie.set_http_only(true);
    cookie.set_same_site(axum_extra::extract::cookie::SameSite::Lax);
    if state.config.public_url.starts_with("https") {
        cookie.set_secure(true);
    }

    let jar = jar.add(cookie);
    Ok((jar, Redirect::to("/")))
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
