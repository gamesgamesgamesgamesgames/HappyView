use axum::extract::{Request, State};
use axum::middleware::Next;
use axum::response::Response;

use crate::AppState;
use crate::error::AppError;

async fn require_feature(
    flag_key: &'static str,
    State(state): State<AppState>,
    req: Request,
    next: Next,
) -> Result<Response, AppError> {
    if !crate::feature_flags::is_enabled(&state.db, flag_key, state.db_backend).await {
        return Err(AppError::FeatureDisabled(format!(
            "The feature '{}' is not currently enabled on this instance",
            flag_key
        )));
    }
    Ok(next.run(req).await)
}

pub async fn require_spaces(
    state: State<AppState>,
    req: Request,
    next: Next,
) -> Result<Response, AppError> {
    require_feature(
        crate::feature_flags::FeatureFlag::SPACES_ENABLED,
        state,
        req,
        next,
    )
    .await
}
