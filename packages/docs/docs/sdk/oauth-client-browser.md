# Browser Client

The browser client handles the full OAuth redirect flow for browser apps authenticating with a HappyView instance. It wraps the [OAuth Client](./oauth-client.md) with Web Crypto, localStorage, and AT Protocol handle/DID resolution.

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
  clientKey: "hvc_your_client_key",
});
```

The client uses Web Crypto and localStorage by default. You can override either:

```typescript
const client = new HappyViewBrowserClient({
  instanceUrl: "https://happyview.example.com",
  clientKey: "hvc_your_client_key",
  crypto: myCustomCryptoAdapter,
  storage: myCustomStorageAdapter,
});
```

:::note
The API client must be registered as a **public** client (no secret) with your app's origin in `allowed_origins`. See [Authentication — API clients](../getting-started/authentication.md#api-clients-confidential-vs-public).
:::

## Login

`login()` resolves the user's handle, discovers their PDS, provisions a DPoP key, and redirects the browser to the PDS authorization server:

```typescript
await client.login("alice.bsky.social");
// Browser redirects — code stops here
```

If you need the authorization URL without redirecting (e.g., for a popup or custom UI), use `prepareLogin()`:

```typescript
const { authorizationUrl, did, state } =
  await client.prepareLogin("alice.bsky.social");

// Open in a popup, new tab, etc.
window.open(authorizationUrl);
```

### What happens during login

1. The handle is resolved to a DID via `resolveHandleToDid`.
2. The DID document is fetched to find the PDS URL.
3. The PDS's OAuth authorization server metadata is fetched.
4. A DPoP key is provisioned from HappyView.
5. PKCE challenge/verifier pairs are generated (one for HappyView's DPoP provisioning, one for the PDS authorization server).
6. The pending auth state is stored in localStorage.
7. The browser is redirected to the PDS authorization endpoint.

## OAuth callback

Your app needs an `/oauth/callback` route. On that page, call `callback()` to complete the token exchange:

```typescript
// On /oauth/callback
const session = await client.callback();
// Session is now stored in localStorage and ready to use
```

`callback()` reads the `code` and `state` from the URL query string, exchanges the code for tokens at the PDS token endpoint, and registers the session with HappyView. The pending auth state is cleaned up automatically.

## Restore session

On subsequent page loads, restore the session from localStorage instead of re-authenticating:

```typescript
const session = await client.restore();
if (session) {
  // User is still logged in
}
```

Returns `null` if no stored session is found.

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

## Logout

```typescript
await client.logout(session.did);
```

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
