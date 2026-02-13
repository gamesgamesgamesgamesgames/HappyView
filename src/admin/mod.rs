mod admins;
pub(crate) mod auth;
pub(crate) mod bootstrap;
mod backfill;
pub(crate) mod hash;
mod lexicons;
mod stats;
mod types;

use axum::routing::{delete, get, post};
use axum::Router;

use crate::AppState;

pub use bootstrap::bootstrap;

pub fn admin_routes(_state: AppState) -> Router<AppState> {
    Router::new()
        .route("/lexicons", post(lexicons::upload_lexicon).get(lexicons::list_lexicons))
        .route("/lexicons/{id}", get(lexicons::get_lexicon).delete(lexicons::delete_lexicon))
        .route("/stats", get(stats::stats))
        .route("/backfill", post(backfill::create_backfill))
        .route("/backfill/status", get(backfill::backfill_status))
        .route("/admins", post(admins::create_admin).get(admins::list_admins))
        .route("/admins/{id}", delete(admins::delete_admin))
}
