use axum::Json;
use axum::extract::State;

use crate::AppState;
use crate::error::AppError;
use crate::tap;

use super::auth::UserAuth;
use super::permissions::Permission;

/// GET /admin/tap/stats — aggregate stats from Tap.
pub(super) async fn tap_stats(
    State(state): State<AppState>,
    auth: UserAuth,
) -> Result<Json<tap::TapStats>, AppError> {
    auth.require(Permission::StatsRead).await?;
    let stats = tap::get_stats(
        &state.http,
        &state.config.tap_url,
        state.config.tap_admin_password.as_deref(),
    )
    .await
    .map_err(AppError::BadGateway)?;

    Ok(Json(stats))
}
