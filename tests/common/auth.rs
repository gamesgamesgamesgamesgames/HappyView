use axum::http::{HeaderName, HeaderValue};
use axum::response::IntoResponse;
use axum_extra::extract::cookie::{Cookie, Key, SignedCookieJar};

/// Build a Cookie header containing a signed session cookie for the given DID.
/// This simulates a user who has completed OAuth and has a session cookie.
pub fn admin_cookie_header(did: &str, cookie_key: &Key) -> (HeaderName, HeaderValue) {
    let jar = SignedCookieJar::new(cookie_key.clone());
    let mut cookie = Cookie::new(happyview::auth::COOKIE_NAME, did.to_string());
    cookie.set_path("/");
    let jar = jar.add(cookie);

    // Build a response to extract the Set-Cookie header with the signed value,
    // then convert it to a Cookie request header.
    let response = jar.into_response();
    let set_cookie_values: Vec<String> = response
        .headers()
        .get_all("set-cookie")
        .iter()
        .filter_map(|v| {
            let s = v.to_str().ok()?;
            // Extract just "name=value" from "name=value; Path=/; ..."
            Some(s.split(';').next()?.to_string())
        })
        .collect();
    let cookie_header = set_cookie_values.join("; ");

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
