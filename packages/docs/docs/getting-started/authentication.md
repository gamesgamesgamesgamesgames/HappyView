# Authentication

HappyView has two distinct authentication surfaces:

- **XRPC** (`/xrpc/*`) — client-level identification via an **API client key** on every request, plus optional user-level AT Protocol OAuth for endpoints that need a specific user's identity (e.g. procedures that write to a PDS).
- **Admin API** (`/admin/*`) — user-level authentication via session cookies, admin API keys, or service auth JWTs, gated by [permissions](../guides/permissions.md).

## Which endpoints require what?

| Endpoint type                       | Client identification    | User authentication                                                                  |
| ----------------------------------- | ------------------------ | ------------------------------------------------------------------------------------ |
| Queries (`GET /xrpc/{method}`)      | `X-Client-Key` required  | Optional — provide a session if the query needs to know who the user is             |
| Procedures (`POST /xrpc/{method}`)  | `X-Client-Key` required  | Required — a live OAuth session so HappyView can proxy writes to the user's PDS     |
| Admin API (`/admin/*`)              | —                        | Required — must be a HappyView user with the right [permissions](../guides/permissions.md) |
| Health check (`GET /health`)        | —                        | —                                                                                    |

## XRPC: API client identification

Every XRPC request — including unauthenticated `GET` queries — must identify itself with a registered API client. The client key is HappyView's rate-limit bucket key and its way of knowing who is calling. A request without one returns `401 Unauthorized` with `Missing client identification`.

Register a client in the dashboard (**Settings > API Clients > New client**) or via `POST /admin/api-clients`. You'll get back an `hvc_…` client key and an `hvs_…` client secret — **the secret is only shown once**, so capture it immediately.

HappyView resolves the client key from the first of:

1. The session cookie, if the user logged in through this client's OAuth flow (the cookie carries the `client_key` that minted it).
2. The `X-Client-Key` request header.
3. A `client_key` query-string parameter.

On top of the client key, HappyView does best-effort validation that the caller actually controls the client:

- If an `Origin` header is present (typical for browser apps), it must match the client's registered `client_uri`.
- Otherwise, an `X-Client-Secret` header may be supplied and must match the stored secret (typical for server-to-server callers).

Both checks currently log warnings on mismatch rather than rejecting the request, but the intent is clear: don't share client keys, and treat the secret like a password.

### Calling a query

```sh
curl 'https://happyview.example.com/xrpc/com.example.feed.getHot' \
  -H 'X-Client-Key: hvc_a1b2c3...'
```

For a server-to-server integration, add the secret:

```sh
curl 'https://happyview.example.com/xrpc/com.example.feed.getHot' \
  -H 'X-Client-Key: hvc_a1b2c3...' \
  -H 'X-Client-Secret: hvs_d4e5f6...'
```

### Logging a user in so you can call procedures

Queries that don't care who is calling need nothing more than the client key. Procedures — and queries whose Lua scripts read the caller's DID — need a real AT Protocol OAuth session. The shape of the flow:

1. Publish a client metadata document at your API client's `client_id_url`.
2. Redirect the user to HappyView's OAuth authorize endpoint with your `hvc_…` key as `client_id`.
3. Exchange the authorization code at the token endpoint using your client key + `hvs_…` secret.
4. HappyView sets a signed session cookie containing the user's DID and your client key. Subsequent XRPC requests made with that cookie are automatically attributed to your client — you don't need to also send `X-Client-Key`.

For procedures, HappyView proxies the write to the user's PDS using the stored OAuth session (see [Proxying procedures](#proxying-procedures-to-the-users-pds) below).

## Admin API: user authentication

Admin endpoints don't use API clients. They require a real HappyView user, identified by one of three methods:

### Session cookie (dashboard)

When you log in to the dashboard via AT Protocol OAuth, HappyView sets a signed, HttpOnly session cookie containing your DID. That cookie is honored on admin endpoints as long as the DID is a HappyView user with the required permission for the call.

### Admin API key

For automation — CI/CD, monitoring, cron jobs — create an [admin API key](../guides/api-keys.md) at **Settings > API Keys** or via `POST /admin/api-keys` and pass it as a bearer token:

```sh
export TOKEN="hv_your-api-key-here"
curl http://localhost:3000/admin/lexicons \
  -H "Authorization: Bearer $TOKEN"
```

A key only carries the permissions selected at creation time and can never exceed the permissions of the user who created it. Admin API keys are not valid for XRPC endpoints — they exist solely for admin API access.

### Service auth JWT

HappyView also accepts standard AT Protocol inter-service auth JWTs in the `Authorization` header. Another AppView, relay, or PDS can sign a short-lived ES256 or ES256K JWT with its DID's signing key; HappyView resolves the issuer's DID document, verifies the signature against the `#atproto` verification method, and treats the issuer DID as the caller identity.

For a service auth JWT to validate:

- `alg` must be `ES256` or `ES256K`.
- `typ` must not be `at+jwt`, `refresh+jwt`, or `dpop+jwt` (those are other token types, not inter-service JWTs).
- `exp` must be in the future.
- The signature must verify against the issuer DID's atproto signing key.

As with the other methods, the resolved DID still has to exist in the HappyView `users` table with the right permissions to hit admin endpoints — service auth gets you identified, not privileged.

### Admin access and the first user

On a fresh deployment, the `users` table is empty. The first authenticated request to any admin endpoint auto-bootstraps that user as the **super user** with all permissions granted — so the first handle to log in owns the instance.

To add more users after that, use `POST /admin/users` or the [dashboard](dashboard.md). You can assign permissions individually or use a template (`viewer`, `operator`, `manager`, `full_access`). See [Admin API](../reference/admin-api.md#user-management) for details.

## Proxying procedures to the user's PDS

When a client calls an XRPC procedure that writes a record, HappyView proxies the write to the user's PDS. There are two auth paths that support this:

- **Cookie auth (dashboard)** — `atrium-oauth` attaches a DPoP proof and a DPoP-bound access token to the outbound request automatically.
- **DPoP key provisioning (third-party apps)** — HappyView uses the app's provisioned DPoP key to generate fresh proofs and attach the stored access token (see below).

A request that only carries an `X-Client-Key` header (no session cookie or DPoP token) can hit queries but can't proxy writes — there's no user to write as. Service auth JWTs and admin API keys similarly don't carry a user session.

## DPoP key provisioning for third-party apps

Third-party apps that want HappyView to make PDS writes on behalf of their users use the **DPoP key provisioning** flow instead of cookie auth. This avoids browser-based redirects through HappyView's domain, which can be blocked by Firefox's Bounce Tracker Protection.

The idea: the app gets a DPoP keypair from HappyView, uses that keypair during its own OAuth flow with the user's PDS, then registers the resulting tokens back with HappyView. From that point on, XRPC requests authenticated with `Authorization: DPoP <access_token>` plus a `DPoP` proof header and `X-Client-Key` will have HappyView proxy writes using the stored session.

### API clients: confidential vs public

API clients have a `client_type` field — either `confidential` (default) or `public`.

- **Confidential clients** authenticate with `X-Client-Key` + `X-Client-Secret` headers on every `/oauth/*` request.
- **Public clients** (browser apps that can't keep a secret) authenticate with `X-Client-Key` header + PKCE. The app sends a `pkce_challenge` (S256) in the body when provisioning a key, then proves possession with `pkce_verifier` when registering a session. Public clients also have `allowed_origins` — the `Origin` header must match.

### The full flow

#### 1. Provision a DPoP key

```
POST /oauth/dpop-keys
X-Client-Key: hvc_...
X-Client-Secret: hvs_...
Content-Type: application/json

{}
```

For public clients, omit `X-Client-Secret` and include the PKCE challenge in the body:

```
POST /oauth/dpop-keys
X-Client-Key: hvc_...
Origin: http://localhost:3000
Content-Type: application/json

{ "pkce_challenge": "base64url..." }
```

Response:

```json
{
  "provision_id": "hvp_...",
  "dpop_key": { "kty": "EC", "crv": "P-256", "x": "...", "y": "...", "d": "..." }
}
```

The `dpop_key` is the private JWK. Use it to generate DPoP proofs during your OAuth flow with the user's PDS.

#### 2. Run OAuth with the user's PDS

Use the provisioned DPoP key as your DPoP keypair in a standard AT Protocol OAuth flow with the user's PDS. HappyView is not involved in this step — the app talks directly to the PDS authorization server.

#### 3. Register the session

After the OAuth callback, register the token set with HappyView:

```
POST /oauth/sessions
X-Client-Key: hvc_...
X-Client-Secret: hvs_...
Content-Type: application/json

{
  "provision_id": "hvp_...",
  "did": "did:plc:user123",
  "access_token": "...",
  "refresh_token": "...",
  "expires_at": "2026-04-17T00:00:00Z",
  "scopes": "atproto transition:generic",
  "pds_url": "https://bsky.social",
  "issuer": "https://bsky.social"
}
```

For public clients, omit `X-Client-Secret` and include the PKCE verifier in the body:

```json
{
  "provision_id": "hvp_...",
  "pkce_verifier": "...",
  "did": "did:plc:user123",
  ...
}
```

Response:

```json
{
  "session_id": "uuid",
  "did": "did:plc:user123"
}
```

#### 4. Make XRPC requests

With a registered session, send XRPC requests using DPoP auth:

```sh
curl -X POST 'https://happyview.example.com/xrpc/com.example.feed.createPost' \
  -H 'X-Client-Key: hvc_...' \
  -H 'Authorization: DPoP <access_token>' \
  -H 'DPoP: <proof_jwt>' \
  -H 'Content-Type: application/json' \
  -d '{"text": "Hello world"}'
```

HappyView validates the DPoP proof, looks up the stored session, and proxies the write to the user's PDS using the provisioned DPoP key to generate a fresh proof.

#### 5. Logout

Confidential clients authenticate with `X-Client-Key` + `X-Client-Secret`:

```
DELETE /oauth/sessions/did:plc:user123
X-Client-Key: hvc_...
X-Client-Secret: hvs_...
```

Public clients must provide a valid DPoP proof to prove they hold the key:

```
DELETE /oauth/sessions/did:plc:user123
X-Client-Key: hvc_...
Authorization: DPoP <access_token>
DPoP: <proof_jwt>
```

This deletes the stored session and the associated DPoP key.

### Security notes

- Private keys and tokens are encrypted at rest with AES-256-GCM using `TOKEN_ENCRYPTION_KEY`.
- DPoP proofs are validated for method, URL, timestamp (5-minute window), access token binding, and JWK thumbprint.
- Scopes requested must include `atproto` and must be a subset of the API client's registered scopes.

## Next steps

- [Permissions](../guides/permissions.md) — full list of permissions and what each one grants
- [API Keys](../guides/api-keys.md) — create scoped admin API keys for automation
- [Admin API — API Clients](../reference/admin-api.md#api-clients) — register API clients and configure rate limits
