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

When a client calls an XRPC procedure that writes a record, HappyView proxies the write to the user's PDS using the user's stored OAuth session. `atrium-oauth` attaches a DPoP proof and a DPoP-bound access token to the outbound request automatically — HappyView doesn't do any manual DPoP handling.

This only works if HappyView has a live OAuth session for the caller, which in practice means the caller logged in through the dashboard or through an API client's OAuth flow. A request that only carries an `X-Client-Key` header (no session cookie) can hit queries but can't be used to proxy writes — there's no user to write as. Service auth JWTs and admin API keys similarly don't carry a user OAuth session.

## Next steps

- [Permissions](../guides/permissions.md) — full list of permissions and what each one grants
- [API Keys](../guides/api-keys.md) — create scoped admin API keys for automation
- [Admin API — API Clients](../reference/admin-api.md#api-clients) — register API clients and configure rate limits
