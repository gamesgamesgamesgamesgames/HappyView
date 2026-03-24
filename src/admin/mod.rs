mod api_keys;
pub(crate) mod auth;
mod backfill;
mod events;
mod labelers;
mod lexicons;
mod network_lexicons;
pub(crate) mod permissions;
mod plugins;
mod rate_limits;
mod records;
mod script_variables;
pub(crate) mod settings;
mod stats;
mod types;
mod users;

use axum::Router;
use axum::routing::{delete, get, patch, post, put};

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
        .route("/events", get(events::list_events))
        .route("/users", post(users::create_user).get(users::list_users))
        .route("/users/transfer-super", post(users::transfer_super))
        .route(
            "/users/{id}",
            get(users::get_user).delete(users::delete_user),
        )
        .route("/users/{id}/permissions", patch(users::update_permissions))
        .route(
            "/api-keys",
            post(api_keys::create_api_key).get(api_keys::list_api_keys),
        )
        .route("/api-keys/{id}", delete(api_keys::revoke_api_key))
        .route(
            "/records",
            get(records::list_records).delete(records::delete_record),
        )
        .route(
            "/records/collection",
            delete(records::delete_collection_records),
        )
        .route(
            "/network-lexicons",
            post(network_lexicons::add).get(network_lexicons::list),
        )
        .route("/network-lexicons/{nsid}", delete(network_lexicons::remove))
        .route(
            "/script-variables",
            post(script_variables::upsert).get(script_variables::list),
        )
        .route("/script-variables/{key}", delete(script_variables::delete))
        .route("/labelers", post(labelers::add).get(labelers::list))
        .route(
            "/labelers/{did}",
            patch(labelers::update).delete(labelers::delete),
        )
        .route(
            "/rate-limits",
            post(rate_limits::upsert).get(rate_limits::list),
        )
        .route("/rate-limits/enabled", put(rate_limits::set_enabled))
        .route("/rate-limits/allowlist", post(rate_limits::add_allowlist))
        .route(
            "/rate-limits/allowlist/{id}",
            delete(rate_limits::remove_allowlist),
        )
        .route("/settings", get(settings::list))
        .route(
            "/settings/logo",
            put(settings::upload_logo).delete(settings::delete_logo),
        )
        .route(
            "/settings/{key}",
            put(settings::upsert).delete(settings::delete),
        )
        .route("/plugins", post(plugins::add).get(plugins::list))
        .route("/plugins/preview", post(plugins::preview))
        .route("/plugins/{id}", delete(plugins::remove))
        .route("/plugins/{id}/reload", post(plugins::reload))
        .route(
            "/plugins/{id}/secrets",
            get(plugins::get_secrets).put(plugins::update_secrets),
        )
}
