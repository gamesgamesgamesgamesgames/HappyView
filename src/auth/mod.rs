pub mod middleware;
pub mod oauth_store;
pub mod routes;
pub mod service_auth;

pub use middleware::Claims;
pub use service_auth::ServiceAuth;

pub const COOKIE_NAME: &str = "happyview_session";
