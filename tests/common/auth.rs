use axum::http::{HeaderName, HeaderValue};
use axum_extra::extract::cookie::{Cookie, Key, SignedCookieJar};

/// Build a Cookie header containing a signed session cookie for the given DID.
/// This simulates a user who has completed OAuth and has a session cookie.
pub fn admin_cookie_header(did: &str, cookie_key: &Key) -> (HeaderName, HeaderValue) {
    let jar = SignedCookieJar::new(cookie_key.clone());
    let mut cookie = Cookie::new(happyview::auth::COOKIE_NAME, did.to_string());
    cookie.set_path("/");
    let jar = jar.add(cookie);

    // Extract the Set-Cookie value and convert to a Cookie request header
    let cookie_header = jar
        .iter()
        .map(|c| format!("{}={}", c.name(), c.value()))
        .collect::<Vec<_>>()
        .join("; ");

    (
        HeaderName::from_static("cookie"),
        HeaderValue::from_str(&cookie_header).unwrap(),
    )
}

/// Build an Authorization header for API key endpoints.
pub fn admin_auth_header(token: &str) -> (HeaderName, HeaderValue) {
    (
        HeaderName::from_static("authorization"),
        HeaderValue::from_str(&format!("Bearer {token}")).unwrap(),
    )
}
