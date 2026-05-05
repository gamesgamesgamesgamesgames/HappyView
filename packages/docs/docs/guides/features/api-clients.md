# API Clients

API clients identify your application to a HappyView instance. Every XRPC request — even unauthenticated queries — must include a client key. This guide walks through creating a client, choosing between public and confidential types, and authenticating users.

For the admin CRUD endpoints, see the [API reference](../../reference/admin/api-clients.md). For the JavaScript SDK, see the [SDK docs](../../sdk/overview.md).

## Concepts

An API client represents **your application**, not individual users. Create one client for your app and use the same client key everywhere. Users authenticate separately via OAuth — the client key identifies _who built the app_, not _who is using it_.

Each client has:

- An `hvc_`-prefixed **client key** — included in every request to identify your app
- An `hvs_`-prefixed **client secret** — used by server-side apps to prove ownership (confidential clients only)
- **Rate limits** — a token bucket that controls how many requests your app can make
- **Scopes** — which lexicons your app is allowed to access

## Public vs. confidential clients

Choose based on where your code runs:

|                        | Confidential                               | Public                                      |
| ---------------------- | ------------------------------------------ | ------------------------------------------- |
| **Use when**           | Server-side apps, CLI tools, bots          | Browser apps, mobile apps                   |
| **Authentication**     | `X-Client-Key` + `X-Client-Secret` headers | `X-Client-Key` + `Origin` header + PKCE     |
| **Can keep a secret?** | Yes                                        | No                                          |
| **Origin validation**  | No                                         | Yes — `Origin` must match `allowed_origins` |
| **PKCE required?**     | No                                         | Yes (S256)                                  |

:::tip
If your app has a backend that can securely store the client secret, use a confidential client even if the frontend is a browser app. The backend can proxy OAuth operations.
:::

## Creating a client

### From the dashboard

Go to **Settings > API Clients > New client** and fill in:

- **Client type** — `confidential` (default) or `public`
- **Name** — a human-readable label (e.g. "My atproto Client")
- **Client ID URL** — URL to your published [OAuth client metadata](https://drafts.aaronpk.com/draft-parecki-oauth-client-id-metadata-document/draft-parecki-oauth-client-id-metadata-document.html) document
- **Client URI** — your app's root domain (e.g. https://example.com)
- **Redirect URIs** — where the PDS should redirect after authorization
- **Allowed origins** — (public clients only) which `Origin` headers to accept
- **Scopes** — `atproto` is always included; add custom scopes if your instance uses them

**Save the client secret immediately.** It is only shown once and is hashed before storage.

### From the API

```sh
curl -X POST http://127.0.0.1:3000/admin/api-clients \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "name": "My atproto Client",
    "client_id_url": "https://example.com/client-metadata.json",
    "client_uri": "https://example.com",
    "redirect_uris": ["https://example.com/oauth/callback"],
    "client_type": "public",
    "allowed_origins": ["https://example.com"]
  }'
```

See the [API reference](../../reference/admin/api-clients.md#create-an-api-client) for all fields.

## Using your client key

Every XRPC request must include the client key. HappyView looks for it in this order:

1. `X-Client-Key` request header (preferred)
2. `client_key` query parameter

### Unauthenticated queries

For public queries that don't need a user identity:

```sh
curl 'https://happyview.example.com/xrpc/com.example.feed.getHot' \
  -H 'X-Client-Key: hvc_a1b2c3...'
```

Server-side callers should also include the secret (since there's no origin to authenticate):

```sh
curl 'https://happyview.example.com/xrpc/com.example.feed.getHot' \
  -H 'X-Client-Key: hvc_a1b2c3...' \
  -H 'X-Client-Secret: hvs_d4e5f6...'
```

### Authenticated requests (user identity)

Procedures — and queries whose scripts need to know who the caller is — require a user's OAuth session. This uses [DPoP authentication](../../getting-started/authentication.md#dpop-key-provisioning-for-third-party-apps), where each request includes a cryptographic proof that the caller holds the right key.

```sh
curl -X POST 'https://happyview.example.com/xrpc/com.example.createPost' \
  -H 'X-Client-Key: hvc_...' \
  -H 'Authorization: DPoP <access_token>' \
  -H 'DPoP: <proof_jwt>' \
  -H 'Content-Type: application/json' \
  -d '{"text": "Hello world"}'
```

## Authenticating users

### Using the JavaScript SDK

The SDK handles the entire DPoP flow. A complete browser example:

```typescript
import { HappyViewBrowserClient } from "@happyview/oauth-client-browser";

const client = new HappyViewBrowserClient({
  instanceUrl: "https://happyview.example.com",
  clientKey: "hvc_your_client_key",
});

// Sign in — redirects to the user's PDS
await client.signIn("alice.bsky.social");
```

On page load, restore a session or process the OAuth callback:

```typescript
const result = await client.init();
if (result) {
  const { session } = result;

  // Make authenticated requests
  const response = await session.fetchHandler(
    "/xrpc/com.example.getStuff?limit=10",
    { method: "GET" },
  );
}
```

For server-side Node.js apps, use the core [`@happyview/oauth-client`](../../sdk/oauth-client.md) package with a confidential client. For type-safe XRPC calls, pair either client with [`@happyview/lex-agent`](../../sdk/lex-agent.md).

### Manual DPoP flow

If you're not using JavaScript, or want to understand the protocol, the DPoP flow has four phases.

#### Phase 1: Provision a DPoP key

Ask HappyView for an ES256 keypair that will be shared between your app and the instance.

**Confidential client:**

```http
POST /oauth/dpop-keys
X-Client-Key: hvc_...
X-Client-Secret: hvs_...
Content-Type: application/json

{}
```

**Public client:**

```http
POST /oauth/dpop-keys
X-Client-Key: hvc_...
Origin: https://example.com
Content-Type: application/json

{"pkce_challenge": "<base64url-encoded S256 challenge>"}
```

**Response:**

```json
{
  "provision_id": "hvp_...",
  "dpop_key": {
    "kty": "EC",
    "crv": "P-256",
    "x": "...",
    "y": "...",
    "d": "..."
  }
}
```

The `dpop_key` is the full private JWK. Store it securely — you'll use it to sign DPoP proofs.

#### Phase 2: OAuth with the user's PDS

Run a standard atproto OAuth flow with the user's PDS authorization server, using the provisioned DPoP key as your keypair. HappyView is not involved in this step.

1. Resolve the user's handle to a DID
2. Resolve the DID document to find the PDS URL
3. Fetch the PDS's OAuth authorization server metadata
4. Redirect the user to the PDS authorization endpoint
5. Exchange the authorization code for tokens (using DPoP proofs signed with the provisioned key)

#### Phase 3: Register the session

After the OAuth callback, register the token set with HappyView so it can proxy requests on behalf of the user.

**Confidential client:**

```http
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

**Public client** — omit the secret, include the PKCE verifier:

```http
POST /oauth/sessions
X-Client-Key: hvc_...
Content-Type: application/json

{
  "provision_id": "hvp_...",
  "pkce_verifier": "...",
  "did": "did:plc:user123",
  "access_token": "...",
  "refresh_token": "...",
  "expires_at": "2026-04-17T00:00:00Z",
  "scopes": "atproto transition:generic",
  "pds_url": "https://bsky.social",
  "issuer": "https://bsky.social"
}
```

#### Phase 4: Make authenticated XRPC requests

With a registered session, sign each request with a DPoP proof:

```sh
curl -X POST 'https://happyview.example.com/xrpc/com.example.createPost' \
  -H 'X-Client-Key: hvc_...' \
  -H 'Authorization: DPoP <access_token>' \
  -H 'DPoP: <proof_jwt>' \
  -H 'Content-Type: application/json' \
  -d '{"text": "Hello world"}'
```

HappyView validates the proof, looks up the stored session, and proxies writes to the user's PDS using the shared DPoP key.

#### Logout

**Confidential:**

```http
DELETE /oauth/sessions/did:plc:user123
X-Client-Key: hvc_...
X-Client-Secret: hvs_...
```

**Public** (must prove key possession):

```http
DELETE /oauth/sessions/did:plc:user123
X-Client-Key: hvc_...
Authorization: DPoP <access_token>
DPoP: <proof_jwt>
```

### DPoP proof format

If you're implementing the flow without the SDK, a DPoP proof JWT looks like this:

**Header:**

```json
{
  "alg": "ES256",
  "typ": "dpop+jwt",
  "jwk": {
    "kty": "EC",
    "crv": "P-256",
    "x": "...",
    "y": "..."
  }
}
```

**Payload:**

```json
{
  "htm": "POST",
  "htu": "https://happyview.example.com/xrpc/com.example.createPost",
  "iat": 1745452800,
  "ath": "<base64url SHA-256 of the access token>",
  "jti": "<unique identifier>"
}
```

Validation rules:

- `htm` must match the HTTP method (case-insensitive)
- `htu` must match the request URL (scheme + host + path, no query string)
- `iat` must be within 5 minutes of the server's clock
- `ath` must be the base64url-encoded SHA-256 hash of the access token
- The JWK thumbprint (RFC 7638, SHA-256) must match the key used during provisioning
- The signature must verify against the embedded public JWK

## Scopes

By default, a client's scopes are just `atproto`. You can add custom scopes when creating or updating the client.

HappyView supports an `include:` directive that expands permission sets defined in lexicons. For example, if your instance has a lexicon `com.example.authBasic` with a `permissions` array in its definition, you can set the client's scopes to:

```
atproto include:com.example.authBasic
```

This expands to include all RPC methods and repository actions defined in that permission set.

## Rate limiting

Each API client has its own token bucket for rate limiting:

- **Capacity** — maximum tokens in the bucket
- **Refill rate** — tokens added per second

If not set on the client, the instance defaults apply (`DEFAULT_RATE_LIMIT_CAPACITY` and `DEFAULT_RATE_LIMIT_REFILL_RATE`).

Rate limit state is returned in response headers:

| Header                | Description                                 |
| --------------------- | ------------------------------------------- |
| `RateLimit-Limit`     | Bucket capacity                             |
| `RateLimit-Remaining` | Tokens remaining                            |
| `RateLimit-Reset`     | Unix timestamp when the bucket will be full |
| `Retry-After`         | Seconds to wait (only on `429` responses)   |

Adjust per-client rate limits via the dashboard or the [admin API](../../reference/admin/api-clients.md#update-an-api-client).

## Security notes

- Client secrets are SHA-256 hashed before storage — HappyView never stores the plaintext.
- DPoP private keys and OAuth tokens are encrypted at rest with AES-256-GCM using the `TOKEN_ENCRYPTION_KEY` environment variable.
- Re-authenticating the same user with the same client upserts the session. The old DPoP key is cleaned up automatically.
- Multiple clients can have active sessions for the same user — sessions are isolated per client.

## Next steps

- [Authentication](../../getting-started/authentication.md) — full protocol details and security model
- [JavaScript SDK](../../sdk/overview.md) — get started with the SDK
- [Admin API — API Clients](../../reference/admin/api-clients.md) — CRUD endpoints
- [Permissions](../admin/permissions.md) — control who can manage API clients
