# Authentication

HappyView uses [AT Protocol OAuth](https://atproto.com/specs/oauth) for authentication, handled natively via the `atrium-oauth` library. HappyView manages the full OAuth flow internally — no external auth service is required.

## Which endpoints require auth?

| Endpoint type | Auth required? |
|---------------|---------------|
| Queries (`GET /xrpc/{method}`) | No |
| Procedures (`POST /xrpc/{method}`) | Yes |
| Admin API (`/admin/*`) | Yes (must be a user with appropriate [permissions](../guides/permissions.md)) |
| Health check (`GET /health`) | No |

Authentication uses signed session cookies set during the OAuth login flow. For programmatic access, API keys (prefixed `hv_`) are also supported via the `Authorization: Bearer` header.

## Logging in via the dashboard

1. Open the dashboard and click **Log in**
2. Enter your AT Protocol handle (e.g. `user.bsky.social`)
3. You'll be redirected to your identity provider's authorization page
4. After approving, you're redirected back to HappyView with a session cookie set

The session cookie is HttpOnly and signed. It persists across browser sessions until you log out or the OAuth session expires.

## Programmatic access

For scripts or CI/CD pipelines, use [API keys](../guides/api-keys.md) instead of OAuth:

```sh
export TOKEN="hv_your-api-key-here"
curl http://localhost:3000/admin/lexicons \
  -H "Authorization: Bearer $TOKEN"
```

API keys are created via the dashboard or `POST /admin/api-keys`. See the [API Keys guide](../guides/api-keys.md) for details.

## How authentication works

HappyView supports three authentication methods:

1. **Session cookie** (web UI) — Set during the OAuth callback flow. The signed cookie contains the user's DID, which HappyView reads on each request.
2. **API key** (programmatic) — Bearer tokens starting with `hv_`. HappyView looks up the key hash in the database to resolve the caller's DID and permissions.
3. **Service auth JWT** (AT Protocol inter-service) — Standard AT Protocol service authentication via signed JWTs. HappyView validates the signature by resolving the issuer's DID document.

For write operations (procedures), HappyView uses the stored OAuth session to proxy writes to the user's PDS. The `atrium-oauth` library handles DPoP proof generation and token refresh automatically.

## Admin access

Admin endpoints require the authenticated user's DID to exist in the `users` table with the appropriate [permissions](../guides/permissions.md). If the table is empty (fresh deployment), the first authenticated request to any admin endpoint auto-bootstraps that user as the **super user** with all permissions granted.

To add more users, use `POST /admin/users` or the [dashboard](dashboard.md). You can assign permissions individually or use a template (`viewer`, `operator`, `manager`, `full_access`). See [Admin API](../reference/admin-api.md#user-management) for details.
