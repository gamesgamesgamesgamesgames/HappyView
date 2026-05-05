# @happyview/oauth-client-browser

Browser OAuth client for authenticating with a [HappyView](https://github.com/gamesgamesgamesgamesgames/happyview) instance using AT Protocol.

Built on top of [`@happyview/oauth-client`](https://www.npmjs.com/package/@happyview/oauth-client) with Web Crypto and localStorage adapters included.

## Installation

```bash
npm install @happyview/oauth-client-browser
```

## Usage

### Setup

```typescript
import { HappyViewBrowserClient } from "@happyview/oauth-client-browser";

const client = new HappyViewBrowserClient({
  instanceUrl: "https://happyview.example.com",
  clientKey: "hvc_your_client_key",
});
```

### Sign In

Redirects the user to their PDS authorization server:

```typescript
await client.signIn("alice.bsky.social");
// User is redirected to their PDS for authorization
```

Or sign in via a popup:

```typescript
const session = await client.signIn("alice.bsky.social", {
  display: "popup",
});
```

If you need the authorization URL without an immediate redirect, use `prepareLogin`:

```typescript
const { authorizationUrl, did, state } =
  await client.prepareLogin("alice.bsky.social");
```

### Initialization

On page load, call `init()` to restore a session or process an OAuth callback:

```typescript
const result = await client.init();
if (result) {
  const { session } = result;
  // User is logged in
}
```

### Authenticated Requests

The session's `fetchHandler` attaches DPoP proof headers automatically. Pass it a path (relative to the HappyView instance) or a full URL:

```typescript
const response = await session.fetchHandler(
  "/xrpc/com.example.getStuff?limit=10",
  { method: "GET" },
);
```

### Revoke Session

```typescript
await client.revoke("did:plc:abc123");
```

## Exports

This package re-exports everything from `@happyview/oauth-client`, plus:

- `HappyViewBrowserClient` -- the main browser client
- `LocalStorageAdapter` -- `StorageAdapter` backed by `window.localStorage`
- `WebCryptoAdapter` -- `CryptoAdapter` backed by the Web Crypto API
- `resolveHandleToDid` -- resolve an AT Protocol handle to a DID
- `resolveDidDocument` -- fetch a DID document
- `resolvePdsUrl` -- extract the PDS URL from a DID document
- `resolveAuthServerMetadata` -- fetch OAuth authorization server metadata from a PDS
