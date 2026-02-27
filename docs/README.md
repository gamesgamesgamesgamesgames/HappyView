# HappyView

HappyView is the best way to build an [AppView](https://atproto.com/guides/glossary#app-view) for the [AT Protocol](https://atproto.com). Upload your [lexicon](reference/glossary.md#at-protocol-terms) schemas and get a fully functional AppView, complete with [XRPC](reference/glossary.md#at-protocol-terms) endpoints, OAuth, real-time network sync, and historical [backfill](guides/backfill.md), without writing a single line of server code.

Building an AppView from scratch means wiring up firehose connections, record storage, XRPC routing, OAuth flows, and PDS write proxying before you can even think about your application. HappyView handles all of that. Define your data model with lexicons, add custom logic with Lua scripts when you need it, and ship your app.

## Features

- 📜 **Lexicon-Driven**: Upload your lexicon schemas and HappyView generates fully functional XRPC query and procedure endpoints automatically, no code required
- 🔄 **Real-Time Sync**: Records stream in from the AT Protocol network in real-time via [Tap](https://github.com/bluesky-social/indigo/tree/main/cmd/tap), with cryptographic verification and backfill via the admin API
- 🔐 **OAuth Built In**: [AIP](https://github.com/graze-social/aip) handles authentication, and writes are proxied back to the user's PDS, so there's no session management needed
- 🌙 **Lua Scripting**: Add custom query and procedure logic with Lua scripts that have full access to the record database
- 🗄️ **Automatic Indexing**: HappyView indexes relevant records into PostgreSQL as they arrive, ready to query
- 🌐 **Network Lexicons**: Fetch lexicon schemas directly from the AT Protocol network via DNS authority resolution
- ⚡ **Hot Reloading**: Upload or update lexicons at runtime, and new endpoints are available immediately with no restart
- 🛠️ **Admin Dashboard**: Manage lexicons, monitor record stats, and run backfill jobs through a built-in admin API

## Design Principles

- **Schema-first**: Your Lexicons are the source of truth. Upload a schema and HappyView derives endpoints, indexing rules, and network sync from it. You describe _what_ your data looks like; HappyView figures out the rest.

- **Zero boilerplate**: HappyView handles AppView infrastructure (firehose, backfill, OAuth, PDS proxying) for you. You should be writing application logic from minute one, not plumbing.

- **Runtime-configurable**: Lexicons can be added, updated, and removed without restarting the server. New endpoints and sync rules take effect immediately, so you can iterate on your data model in real time.

- **Protocol-native**: HappyView works with _any_ PDS, resolves DIDs through the directory, and follows AT Protocol conventions. It's a first-class citizen of the network, not a wrapper around it.

## Next Steps

- [Quickstart](getting-started/deployment/railway.md): Deploy HappyView on Railway or run it locally
- [Lexicons](guides/lexicons.md): Upload lexicon schemas and start indexing records
- [Lua Scripting](guides/scripting.md): Write custom query and procedure logic
