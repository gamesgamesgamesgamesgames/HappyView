-- Stores redirect URIs for cross-origin login flows (e.g., Pentaract → HappyView).
-- Keyed by the OAuth state parameter so we can look up the redirect target
-- when the PDS callback arrives, without relying on third-party cookies.
CREATE TABLE auth_login_redirects (
    state TEXT PRIMARY KEY,
    redirect_uri TEXT NOT NULL,
    created_at TEXT NOT NULL,
    expires_at TEXT NOT NULL
);

CREATE INDEX idx_auth_login_redirects_expires ON auth_login_redirects(expires_at);
