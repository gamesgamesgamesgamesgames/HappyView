# JavaScript SDK

HappyView provides JavaScript packages for building third-party apps that authenticate with a HappyView instance and make XRPC requests on behalf of users.

| Package                                                                                       | Purpose                                                                                                                    |
| --------------------------------------------------------------------------------------------- | -------------------------------------------------------------------------------------------------------------------------- |
| [`@happyview/lex-agent`](https://npmx.dev/package/@happyview/lex-agent)                       | Recommended — type-safe XRPC via [`@atproto/lex`](https://npmx.dev/package/@atproto/lex) `Client` with HappyView DPoP auth |
| [`@happyview/oauth-client`](https://npmx.dev/package/@happyview/oauth-client)                 | Platform-agnostic core — DPoP key provisioning, session management, authenticated fetch                                    |
| [`@happyview/oauth-client-browser`](https://npmx.dev/package/@happyview/oauth-client-browser) | Browser OAuth wrapper for apps already using `@atproto/oauth-client-browser`                                               |

## Which package do I need?

**Starting a new app?** Use `@happyview/lex-agent` with `@atproto/lex`. It gives you type-safe XRPC calls through a `Client` that routes requests to your HappyView instance with DPoP authentication. This is the recommended way to interact with HappyView from JavaScript.

**Already using `@atproto/oauth-client-browser`?** Add `@happyview/oauth-client-browser` to get a `HappyViewBrowserClient` that handles the HappyView-specific DPoP key provisioning and session registration on top of the standard atproto OAuth flow.

**Building a server-side app or something more custom?** Use `@happyview/oauth-client` directly and provide your own `CryptoAdapter` and `StorageAdapter`.

## How it works

Third-party apps authenticate using HappyView's [DPoP key provisioning](../getting-started/authentication.md#dpop-key-provisioning-for-third-party-apps) flow:

1. The SDK requests a DPoP keypair from the HappyView instance.
2. Your app runs a standard atproto OAuth flow with the user's PDS using that keypair.
3. The SDK registers the resulting tokens with HappyView.
4. All subsequent XRPC requests are authenticated with DPoP proofs — HappyView handles its own lexicons locally and proxies standard atproto writes to the user's PDS.

## Quick start

```bash
npm install @happyview/lex-agent @happyview/oauth-client-browser @atproto/lex
```

```typescript
import { Client } from "@atproto/lex";
import { HappyViewBrowserClient } from "@happyview/oauth-client-browser";
import { createAgent } from "@happyview/lex-agent";

// Set up the OAuth client
const oauthClient = new HappyViewBrowserClient({
  instanceUrl: "https://happyview.example.com",
  clientId: "https://example.com/oauth-client-metadata.json",
  clientKey: "hvc_your_client_key",
});

// Login — redirects to the user's PDS
await oauthClient.login("alice.bsky.social");

// On /oauth/callback — complete the flow
const session = await oauthClient.callback();

// Create a type-safe Lex client
const agent = createAgent(session);
const lex = new Client(agent);

// Make type-safe XRPC calls
const result = await lex.xrpc(myLexicons.com.example.getGame, {
  params: { slug: "celeste" },
});
```

## Next steps

- [Lex Agent](./lex-agent.md): type-safe XRPC with `@atproto/lex`
- [OAuth Client](./oauth-client.md): platform-agnostic core client
- [Browser Client](./oauth-client-browser.md): browser OAuth redirect flow
- [Authentication](../getting-started/authentication.md): full details on DPoP key provisioning and API client types
