mod admins;
pub(crate) mod auth;
mod backfill;
mod lexicons;
mod network_lexicons;
mod stats;
mod types;

use axum::Router;
use axum::routing::{delete, get, post};

use crate::AppState;

pub fn admin_routes(_state: AppState) -> Router<AppState> {
    Router::new()
        .route(
            "/lexicons",
            post(lexicons::upload_lexicon).get(lexicons::list_lexicons),
        )
        .route(
            "/lexicons/{id}",
            get(lexicons::get_lexicon).delete(lexicons::delete_lexicon),
        )
        .route("/stats", get(stats::stats))
        .route("/backfill", post(backfill::create_backfill))
        .route("/backfill/status", get(backfill::backfill_status))
        .route(
            "/admins",
            post(admins::create_admin).get(admins::list_admins),
        )
        .route("/admins/{id}", delete(admins::delete_admin))
        .route(
            "/network-lexicons",
            post(network_lexicons::add).get(network_lexicons::list),
        )
        .route("/network-lexicons/{nsid}", delete(network_lexicons::remove))
}
