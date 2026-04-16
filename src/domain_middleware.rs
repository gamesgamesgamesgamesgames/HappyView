use axum::{
    extract::{Request, State},
    http::StatusCode,
    middleware::Next,
    response::Response,
};
use std::sync::Arc;

use crate::AppState;
use crate::domain::Domain;

pub async fn resolve_domain(
    State(state): State<AppState>,
    mut req: Request,
    next: Next,
) -> Result<Response, (StatusCode, &'static str)> {
    let host = req
        .headers()
        .get("x-forwarded-host")
        .or_else(|| req.headers().get("host"))
        .and_then(|v| v.to_str().ok())
        .map(|h| h.split(':').next().unwrap_or(h))
        .unwrap_or("");

    let domain = state.domain_cache.get(host).await;

    match domain {
        Some(domain) => {
            req.extensions_mut().insert(domain);
            Ok(next.run(req).await)
        }
        None => Err((StatusCode::MISDIRECTED_REQUEST, "Unknown host")),
    }
}

pub fn extract_domain(req: &Request) -> Option<Arc<Domain>> {
    req.extensions().get::<Arc<Domain>>().cloned()
}
