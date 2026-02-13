use axum::http::{HeaderName, HeaderValue};
use wiremock::matchers::{header, method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

use crate::common::fixtures;

/// Build an Authorization header for admin endpoints.
pub fn admin_auth_header(token: &str) -> (HeaderName, HeaderValue) {
    (
        HeaderName::from_static("authorization"),
        HeaderValue::from_str(&format!("Bearer {token}")).unwrap(),
    )
}

/// Mount a mock on the given server that responds to AIP userinfo requests
/// with a successful response containing the given DID.
pub async fn mock_aip_userinfo(mock_server: &MockServer, did: &str) {
    Mock::given(method("GET"))
        .and(path("/oauth/userinfo"))
        .respond_with(ResponseTemplate::new(200).set_body_json(fixtures::userinfo_response(did)))
        .mount(mock_server)
        .await;
}
