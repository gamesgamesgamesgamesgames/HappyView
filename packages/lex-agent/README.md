# @happyview/lex-agent

Adapter that creates an [`@atproto/lex`](https://www.npmjs.com/package/@atproto/lex) `Agent` from a `HappyViewSession`. This lets you use `@atproto/lex`'s type-safe `Client` and `xrpc()` calls with HappyView's DPoP authentication.

All XRPC requests made through the agent are routed to your HappyView instance. HappyView handles requests for its own lexicons locally and proxies standard AT Protocol methods (e.g., `com.atproto.repo.createRecord`) to the user's PDS.

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

// Authenticate with HappyView
const client = new HappyViewBrowserClient({
  instanceUrl: "https://happyview.example.com",
  clientKey: "hvc_your_client_key",
});
const session = await client.restore();

// Create a Lex agent from the session
const agent = createAgent(session);
const lex = new Client(agent);

// Make type-safe XRPC calls
const game = await lex.xrpc(myLexicons.com.example.getGame, {
  params: { slug: "celeste" },
});
```

## API

### `createAgent(session: HappyViewSession): Agent`

Creates an `@atproto/lex` `Agent` from a `HappyViewSession`. The returned agent:

- Exposes the session's DID via `agent.did`
- Delegates all fetch requests to `session.fetchHandler`, which attaches DPoP authentication headers and prepends the HappyView instance URL
