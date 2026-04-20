# Lex Agent

The Lex agent adapter is the recommended way to interact with HappyView from JavaScript. It creates an [`@atproto/lex`](https://www.npmjs.com/package/@atproto/lex) `Agent` from a `HappyViewSession`, so you can use `@atproto/lex`'s type-safe `Client` to make XRPC calls with HappyView's DPoP authentication. All requests are routed to your HappyView instance, which handles its own lexicons locally and proxies standard atproto methods (e.g., `com.atproto.repo.createRecord`) to the user's PDS.

The adapter gives you lexicon-level type checking on parameters, input bodies, and responses, and works with any library or tool that accepts an `@atproto/lex` `Agent`.

## Installation

```bash
npm install @happyview/lex-agent @atproto/lex
```

`@atproto/lex` is a peer dependency (`>=0.0.20`).

## Usage

```typescript
import { Client } from "@atproto/lex";
import { HappyViewBrowserClient } from "@happyview/oauth-client-browser";
import { createAgent } from "@happyview/lex-agent";

const client = new HappyViewBrowserClient({
  instanceUrl: "https://happyview.example.com",
  clientKey: "hvc_your_client_key",
});

// Authenticate (or restore a session)
const session = await client.restore();

// Create a Lex agent from the session
const agent = createAgent(session);
const lex = new Client(agent);
```

## Type-safe XRPC calls

With a `Client` instance, you can make type-safe XRPC calls using lexicon definitions:

```typescript
// Query
const result = await lex.xrpc(myLexicons.com.example.getGame, {
  params: { slug: "celeste" },
});

// Procedure
await lex.xrpc(myLexicons.com.example.createPost, {
  input: { text: "Hello from HappyView!" },
});
```

The `Client` validates parameters and return types against the lexicon schema at the type level, so your IDE catches mismatches before runtime.

## API

### `createAgent(session: HappyViewSession): Agent`

Creates an `@atproto/lex` `Agent` from a `HappyViewSession`.

- `agent.did` — the session user's DID
- `agent.fetchHandler(path, init)` — delegates to `session.fetchHandler`, which attaches DPoP authentication headers and prepends the HappyView instance URL to relative paths
