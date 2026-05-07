# @happyview/oauth-client-node

Node.js OAuth client for authenticating with a [HappyView](https://github.com/gamesgamesgamesgamesgames/happyview) instance using AT Protocol.

Built on top of [`@happyview/oauth-client`](https://www.npmjs.com/package/@happyview/oauth-client). Matches the API surface of [`@atproto/oauth-client-node`](https://www.npmjs.com/package/@atproto/oauth-client-node).

## Installation

```bash
npm install @happyview/oauth-client-node
```

## Usage

### Setup

```typescript
import { HappyViewNodeClient } from "@happyview/oauth-client-node";

const client = new HappyViewNodeClient({
  instanceUrl: "https://happyview.example.com",
  clientId: "https://example.com/oauth-client-metadata.json",
  clientKey: "hvc_your_client_key",
  clientSecret: "hvs_your_secret", // optional, for confidential clients
  redirectUri: "https://example.com/oauth/callback",
  storage: myStorageAdapter,
});
```

### Authorize

Generate an authorization URL and redirect the user:

```typescript
const url = await client.authorize("alice.bsky.social");
// Redirect the user to url.href
```

With options:

```typescript
const url = await client.authorize("alice.bsky.social", {
  scope: "atproto transition:generic",
  redirect_uri: "https://example.com/alt-callback",
  prompt: "login",
  display: "page",
});
```

### Callback

On your callback route, process the OAuth response:

```typescript
const params = new URLSearchParams(req.url.split("?")[1]);
const { session, state } = await client.callback(params);
```

### Restore Session

Restore a session by DID:

```typescript
const session = await client.restore("did:plc:abc123");
```

### Session

```typescript
// Authenticated requests
const response = await session.fetchHandler(
  "/xrpc/com.example.getStuff?limit=10",
  { method: "GET" },
);

// Token metadata
const info = session.getTokenInfo();
// { sub, scope, iss, aud }

// Self-revoke
await session.signOut();
```

### Using with @atproto/api

```typescript
import { Agent } from "@atproto/api";

const agent = new Agent(session);
const profile = await agent.getProfile({ actor: agent.did });
```

### Revoke Session

```typescript
await client.revoke("did:plc:abc123");
// or
await session.signOut();
```

### Abort Request

```typescript
const url = await client.authorize("alice.bsky.social");
// ...later:
await client.abortRequest(url);
```

### Validate Client Metadata

```typescript
const metadata = await HappyViewNodeClient.fetchMetadata({
  clientId: "https://example.com/oauth-client-metadata.json",
});
```

### Identity Resolution

```typescript
const did = await client.handleResolver.resolve("alice.bsky.social");
const doc = await client.didResolver.resolve(did);
```

## Storage

You must provide a `StorageAdapter`. The built-in `MemoryStorage` works for testing but won't survive restarts:

```typescript
import { MemoryStorage } from "@happyview/oauth-client-node";

const client = new HappyViewNodeClient({
  // ...
  storage: new MemoryStorage(),
});
```

For production, implement the `StorageAdapter` interface backed by your database or cache:

```typescript
interface StorageAdapter {
  get(key: string): Promise<string | null>;
  set(key: string, value: string): Promise<void>;
  delete(key: string): Promise<void>;
}
```

## Exports

This package re-exports everything from `@happyview/oauth-client`, plus:

- `HappyViewNodeClient` -- the main Node.js client
- `AuthorizeOptions`, `CallbackOptions`, `HappyViewNodeClientOptions` types
