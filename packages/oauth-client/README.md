# @happyview/oauth-client

Core OAuth client for authenticating with a [HappyView](https://github.com/gamesgamesgamesgamesgames/happyview) instance.

This is a platform-agnostic package. If you're building a browser app, use [`@happyview/oauth-client-browser`](https://www.npmjs.com/package/@happyview/oauth-client-browser) instead. It wraps this package with Web Crypto, localStorage, and a complete OAuth redirect flow.

## Installation

```bash
npm install @happyview/oauth-client
```

## Usage

`HappyViewOAuthClient` manages DPoP key provisioning, session registration, and session restoration lifecycle. You provide a `CryptoAdapter` and optional `StorageAdapter` for your platform.

```typescript
import { HappyViewOAuthClient } from "@happyview/oauth-client";

const client = new HappyViewOAuthClient({
  instanceUrl: "https://happyview.example.com",
  clientKey: "hvc_your_client_key",
  clientSecret: "hvs_your_secret", // optional, for confidential clients (server-to-server)
  crypto: myCryptoAdapter,
  storage: myStorageAdapter, // optional, defaults to in-memory
});
```

### DPoP Key Provisioning

Request a DPoP keypair from the HappyView instance:

```typescript
const { provisionId, dpopKey, pkceVerifier } = await client.provisionDpopKey();
```

### Session Registration

After completing OAuth authorization with the user's PDS, register the session with HappyView:

```typescript
const session = await client.registerSession({
  provisionId,
  pkceVerifier,
  did: "did:plc:abc123",
  accessToken: tokens.access_token,
  refreshToken: tokens.refresh_token,
  scopes: "atproto",
  pdsUrl: "https://pds.example.com",
  issuer: tokens.iss,
  dpopKey,
});
```

### Making Authenticated Requests

The returned `HappyViewSession` provides a `fetchHandler` that automatically attaches DPoP proof headers:

```typescript
const response = await session.fetchHandler("/xrpc/com.example.getStuff", {
  method: "GET",
});
```

### Session Restoration

Restore a previously stored session:

```typescript
// Restore the last active session
const session = await client.restore();

// Or restore a specific user's session
const session = await client.restoreSession("did:plc:abc123");
```

### Logout

```typescript
await client.deleteSession("did:plc:abc123");
```

## Adapters

### CryptoAdapter

Implement this interface for your platform's cryptographic primitives:

```typescript
interface CryptoAdapter {
  generatePkceVerifier(): Promise<string>;
  computePkceChallenge(verifier: string): Promise<string>;
  signEs256(privateKey: JsonWebKey, payload: Uint8Array): Promise<Uint8Array>;
  sha256(data: Uint8Array): Promise<Uint8Array>;
  getRandomValues(length: number): Uint8Array;
}
```

### StorageAdapter

Implement this interface to persist sessions across restarts:

```typescript
interface StorageAdapter {
  get(key: string): Promise<string | null>;
  set(key: string, value: string): Promise<void>;
  delete(key: string): Promise<void>;
}
```

If no `StorageAdapter` is provided, sessions are stored in memory and will not survive page reloads or process restarts.
