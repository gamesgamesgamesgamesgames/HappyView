# HappyView

HappyView is the best way to build an [AppView](https://atproto.com/guides/glossary#app-view) for the [AT Protocol](https://atproto.com). Upload your [lexicon](reference/glossary.md#at-protocol-terms) schemas and get a fully functional AppView, complete with [XRPC](reference/glossary.md#at-protocol-terms) endpoints, OAuth, real-time network sync, and historical [backfill](guides/backfill.md), without writing a single line of server code.

Building an AppView from scratch means wiring up firehose connections, record storage, XRPC routing, OAuth flows, and PDS write proxying before you can even think about your application. HappyView handles all of that. Define your data model with lexicons, add custom logic with Lua scripts when you need it, and ship your app.

## Features

- **Schema-driven endpoints.** Upload a [lexicon](guides/lexicons.md) and HappyView generates XRPC query and procedure routes, storage, and indexing from it — updatable at runtime with no restart.
- **Network sync built in.** Real-time record streaming via [Jetstream](https://github.com/bluesky-social/jetstream), historical [backfill](guides/backfill.md) from each user's PDS, and AT Protocol OAuth with DPoP-bound proxy writes back to the PDS.
- **Customize with Lua, hooks, and plugins.** [Lua scripts](guides/scripting.md) for query and procedure logic, [index hooks](guides/index-hooks.md) that fire on every record change, WASM [plugins](guides/plugins.md) for external platform integration, and [labeler](guides/labelers.md) subscriptions for content moderation.
- **Protocol-native.** Works with any PDS, resolves DIDs through the directory, and fetches [network lexicons](guides/lexicons.md#network-lexicons) via DNS authority resolution.
- **Full admin surface.** Built-in [dashboard](getting-started/dashboard.md) and [admin API](reference/admin-api.md) for managing lexicons, users, API keys, API clients, backfill jobs, and plugins.

## Design Principles

- **Schema-first**: Your Lexicons are the source of truth. Upload a schema and HappyView derives endpoints, indexing rules, and network sync from it. You describe _what_ your data looks like; HappyView figures out the rest.

- **Zero boilerplate**: HappyView handles AppView infrastructure (firehose, backfill, OAuth, PDS proxying) for you. You should be writing application logic from minute one, not plumbing.

- **Runtime-configurable**: Lexicons can be added, updated, and removed without restarting the server. New endpoints and sync rules take effect immediately, so you can iterate on your data model in real time.

- **Protocol-native**: HappyView works with _any_ PDS, resolves DIDs through the directory, and follows AT Protocol conventions. It's a first-class citizen of the network, not a wrapper around it.

## Next Steps

- [Quickstart](getting-started/deployment/railway.md): Deploy HappyView on Railway or run it locally
- [Lexicons](guides/lexicons.md): Upload lexicon schemas and start indexing records
- [Lua Scripting](guides/scripting.md): Write custom query and procedure logic
- [Index Hooks](guides/index-hooks.md): React to record changes in real time
- [Labelers](guides/labelers.md): Subscribe to external labelers and manage content labels
- [Plugins](guides/plugins.md): Integrate with external platforms using WASM plugins
- [Event Logs](guides/event-logs.md): Monitor system activity, debug script errors, and audit admin actions
