# Browser Client

The browser client handles the full OAuth redirect flow for browser apps authenticating with a HappyView instance. It wraps the [OAuth Client](./oauth-client.md) with Web Crypto, localStorage, and atproto handle/DID resolution.

If you're starting a new app, consider using [`@happyview/lex-agent`](./lex-agent.md) with `@atproto/lex` instead — it provides type-safe XRPC calls and is the recommended way to interact with HappyView. This package is primarily useful if your app already uses `@atproto/oauth-client-browser` and you want to add HappyView authentication alongside it.

## Installation

```bash
npm install @happyview/oauth-client-browser
```

## Setup

```typescript
import { HappyViewBrowserClient } from "@happyview/oauth-client-browser";

const client = new HappyViewBrowserClient({
  instanceUrl: "https://happyview.example.com",
  clientId: "https://example.com/oauth-client-metadata.json",
  clientKey: "hvc_your_client_key",
});
```

| Option        | Required | Description                                                                   |
| ------------- | -------- | ----------------------------------------------------------------------------- |
| `instanceUrl` | Yes      | The HappyView instance URL                                                    |
| `clientId`    | Yes      | URL where your app serves its [OAuth client metadata](#oauth-client-metadata) |
| `clientKey`   | Yes      | API client key from the HappyView admin dashboard                             |
| `redirectUri` | No       | OAuth callback URL. Defaults to `${window.location.origin}/oauth/callback`    |
| `scopes`      | No       | OAuth scopes to request. Defaults to `"atproto"`                              |
| `storage`     | No       | Custom storage adapter. Defaults to localStorage                              |
| `fetch`       | No       | Custom fetch implementation                                                   |

The client uses localStorage by default. You can override it:

```typescript
const client = new HappyViewBrowserClient({
  instanceUrl: "https://happyview.example.com",
  clientId: "https://example.com/oauth-client-metadata.json",
  clientKey: "hvc_your_client_key",
  storage: myCustomStorageAdapter,
});
```

:::note
The API client must be registered as a **public** client (no secret) with your app's origin in `allowed_origins`. See [Authentication — API clients](../getting-started/authentication.md#api-clients-confidential-vs-public).
:::

## Sign in

`signIn()` resolves the user's handle, discovers their PDS, provisions a DPoP key, and redirects the browser to the PDS authorization server:

```typescript
await client.signIn("alice.bsky.social");
// Browser redirects — code stops here
```

To sign in via a popup window instead:

```typescript
const session = await client.signIn("alice.bsky.social", {
  display: "popup",
});
```

Or use the explicit methods:

```typescript
// Full-page redirect (equivalent to signIn without display option)
await client.signInRedirect("alice.bsky.social");

// Popup window
const session = await client.signInPopup("alice.bsky.social");
```

If you need the authorization URL without redirecting (e.g., for a custom UI), use `prepareLogin()`:

```typescript
const { authorizationUrl, did, state } =
  await client.prepareLogin("alice.bsky.social");
```

:::note
`login()` still works as an alias for `signInRedirect()`.
:::

### What happens during sign in

1. The handle is resolved to a DID via `resolveHandleToDid`.
2. The DID document is fetched to find the PDS URL.
3. The PDS's OAuth authorization server metadata is fetched.
4. A DPoP key is provisioned from HappyView.
5. PKCE challenge/verifier pairs are generated (one for HappyView's DPoP provisioning, one for the PDS authorization server).
6. The pending auth state is stored in localStorage.
7. The browser is redirected to the PDS authorization endpoint (or a popup is opened).

## Initialization

On page load, call `init()` to automatically handle both session restoration and OAuth callbacks:

```typescript
const result = await client.init();
if (result) {
  const { session, state } = result;
  // session is ready to use
}
```

`init()` checks the URL for OAuth callback parameters. If found, it processes the callback and returns `{ session, state }`. Otherwise, it tries to restore the last active session from localStorage.

For more control, use the specific methods:

```typescript
// Restore only — ignores callback params in the URL
const result = await client.initRestore();
if (result) {
  const { session } = result;
}

// Callback only — throws if no callback params are present
const { session, state } = await client.initCallback();
```

### Restoring a specific session

To restore a specific user's session by DID:

```typescript
const session = await client.restore("did:plc:abc123");
```

Calling `restore()` with no arguments returns the last active session, or `null` if none is found.

:::note
`callback()` still works as a standalone method that processes the OAuth callback and returns a session directly.
:::

## Detecting callback params

`readCallbackParams()` checks the current URL for OAuth callback parameters without processing them. This is useful when your app uses client-side routing and needs to detect callbacks before the router changes the URL:

```typescript
const params = client.readCallbackParams();
if (params) {
  // URL contains OAuth callback params — process them
  const { session } = await client.initCallback();
}
```

## Authenticated requests

The session's `fetchHandler` attaches DPoP proof headers automatically:

```typescript
const response = await session.fetchHandler(
  "/xrpc/com.example.getStuff?limit=10",
  { method: "GET" },
);

const data = await response.json();
```

Pass a relative path (prepends the HappyView instance URL) or a full URL (used as-is).

## Revoke session

```typescript
await client.revoke(session.did);
```

:::note
`logout()` still works as an alias for `revoke()`.
:::

## Resolution utilities

The browser client exports the resolution functions it uses internally. These are useful if you need to resolve handles or discover PDS URLs outside of the login flow:

```typescript
import {
  resolveHandleToDid,
  resolveDidDocument,
  resolvePdsUrl,
  resolveAuthServerMetadata,
} from "@happyview/oauth-client-browser";

const did = await resolveHandleToDid("alice.bsky.social");
const doc = await resolveDidDocument(did);
const pdsUrl = resolvePdsUrl(doc);
const authMeta = await resolveAuthServerMetadata(pdsUrl);
```

## OAuth client metadata

Your app must serve an OAuth client metadata JSON document at the URL you pass as `clientId`. The PDS fetches this during authorization to validate the redirect URI and display your app's information.

Example for a Next.js app:

```typescript
// src/app/oauth-client-metadata.json/route.ts
import { type NextRequest } from "next/server";

export function GET(request: NextRequest) {
  const origin = request.nextUrl.origin;

  return Response.json({
    client_id: `${origin}/oauth-client-metadata.json`,
    client_name: "My App",
    client_uri: origin,
    redirect_uris: [`${origin}/oauth/callback`],
    token_endpoint_auth_method: "none",
    grant_types: ["authorization_code", "refresh_token"],
    scope: "atproto",
    application_type: "web",
    dpop_bound_access_tokens: true,
  });
}
```

For a static site, serve a plain JSON file at `/oauth-client-metadata.json`.

The `redirect_uris` array must include the `redirectUri` your client is configured with (defaults to `${origin}/oauth/callback`).

## Re-exports

This package re-exports everything from `@happyview/oauth-client`, so you don't need to install the core package separately. All types, error classes, and utilities are available:

```typescript
import {
  HappyViewBrowserClient,
  HappyViewSession,
  ApiError,
  type CryptoAdapter,
  type StorageAdapter,
} from "@happyview/oauth-client-browser";
```
