# Authentication

HappyView uses [AT Protocol OAuth](https://atproto.com/specs/oauth) for authentication, handled by an external [AIP](https://github.com/graze-social/aip) instance. HappyView does not store credentials or issue tokens: all OAuth is delegated to AIP.

## Which endpoints require auth?

| Endpoint type | Auth required? |
|---------------|---------------|
| Queries (`GET /xrpc/{method}`) | No |
| Procedures (`POST /xrpc/{method}`) | Yes |
| Admin API (`/admin/*`) | Yes (must be an admin) |
| Health check (`GET /health`) | No |

Authenticated requests must include an `Authorization` header with a token issued by AIP:

```
Authorization: Bearer <token>
```

## Getting a token from the dashboard

The easiest way to get a token for CLI or curl usage is through the [web dashboard](dashboard.md):

1. Open the dashboard and log in with your AT Protocol identity
2. Open your browser's developer tools (F12 or Cmd+Shift+I)
3. Go to **Application** (Chrome) or **Storage** (Firefox) > **Session Storage**
4. Find the entry for your dashboard's URL
5. Copy the value of the `session` key: this contains your access token

You can then use it in curl:

```sh
export TOKEN="your-token-here"
curl http://localhost:3000/admin/lexicons \
  -H "Authorization: Bearer $TOKEN"
```

Tokens expire based on AIP's configuration. When a token expires, log in again through the dashboard to get a new one.

## Programmatic access

For scripts or applications that need to authenticate programmatically, you'll need to implement the AT Protocol OAuth flow against your AIP instance. This involves:

1. Registering an OAuth client with AIP
2. Redirecting the user to AIP's authorization endpoint
3. Exchanging the authorization code for an access token
4. Using that token with HappyView

See the [AIP documentation](https://github.com/graze-social/aip) for endpoint details and the [ATProto OAuth spec](https://atproto.com/specs/oauth) for the full protocol.

## How token validation works

When HappyView receives an authenticated request, it forwards the token to AIP's `/oauth/userinfo` endpoint. AIP responds with the user's DID, which HappyView uses to:

- Identify who is making the request
- Proxy writes to the correct PDS
- Check admin permissions (for admin endpoints)

Token validation happens on every request; there is no local token caching.

## Admin access

Admin endpoints require the authenticated user's DID to exist in the `admins` table. If the table is empty (fresh deployment), the first authenticated request to any admin endpoint auto-bootstraps that user as the initial admin.

To add more admins, use `POST /admin/admins` or the [dashboard](dashboard.md). See [Admin API](../reference/admin-api.md#admin-management) for details.
