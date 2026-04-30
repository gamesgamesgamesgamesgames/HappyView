use axum::Json;
use axum::extract::State;

use crate::AppState;
use crate::error::AppError;
use crate::feature_flags;

use super::auth::UserAuth;
use super::permissions::Permission;

pub(super) async fn list(
    State(state): State<AppState>,
    auth: UserAuth,
) -> Result<Json<Vec<feature_flags::FeatureFlagStatus>>, AppError> {
    auth.require(Permission::SettingsManage).await?;
    let flags = feature_flags::list_flags(&state.db, state.db_backend).await;
    Ok(Json(flags))
}
