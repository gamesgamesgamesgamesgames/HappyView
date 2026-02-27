# Glossary

Key terms used throughout the HappyView documentation. For a broader introduction to the AT Protocol, see the [official ATProto glossary](https://atproto.com/guides/glossary).

## AT Protocol terms

**AppView** — A backend service that indexes AT Protocol records and serves them through an API. HappyView is an AppView. See the [ATProto docs](https://atproto.com/guides/glossary#app-view) for more.

**DID** (Decentralized Identifier) — A persistent, globally unique identifier for an account (e.g. `did:plc:abc123`).

**Firehose** — A real-time stream of all record events (creates, updates, deletes) across the AT Protocol network. HappyView consumes this via [Tap](https://github.com/bluesky-social/indigo/tree/main/cmd/tap).

**Handle** — A human-readable name for an account (e.g. `user.bsky.social`). Handles resolve to a DID via DNS or the PLC directory.

**Lexicon** — A schema definition for AT Protocol data types and API methods. Lexicons define what records look like, what endpoints exist, and what parameters they accept. See [Lexicons](../guides/lexicons.md).

**NSID** (Namespaced Identifier) — A reverse-DNS identifier for a lexicon (e.g. `xyz.statusphere.status`). The authority is everything except the last segment.

**PDS** (Personal Data Server) — The server that hosts a user's data. Users can be on any PDS — there's no single server. HappyView proxies writes back to each user's PDS.

**PLC directory** — A public service (e.g. `plc.directory`) that maps DIDs to their DID documents, which contain the user's PDS endpoint and other metadata.

**Record** — A single piece of data in an AT Protocol repository, identified by an AT URI (e.g. `at://did:plc:abc/xyz.statusphere.status/abc123`).

**Relay** — A network service that aggregates repository data from many PDSes. HappyView queries the relay during [backfill](../guides/backfill.md) to discover which repos contain records for a given collection, then delegates the actual record fetching to Tap.

**rkey** (Record Key) — The unique key for a record within a collection and repo. These are most commonly TIDs (timestamp-based) or NSIDs.

**TID** (Timestamp Identifier) — A 13-character sortable identifier used as a record key. Generated from the current timestamp.

**XRPC** — The HTTP-based RPC protocol used by the AT Protocol. Query methods map to GET requests, procedure methods map to POST requests. See [XRPC API](xrpc-api.md).

## HappyView-specific terms

**AIP** — [Authentication and Identity Provider](https://github.com/graze-social/aip). An external service that handles AT Protocol OAuth for HappyView. Issues Bearer tokens used for authentication.

**Backfill** — The process of bulk-indexing existing records from the network. HappyView discovers repos via the relay and delegates record fetching to Tap. Runs when a new record-type lexicon is uploaded or triggered manually. See [Backfill](../guides/backfill.md).

**Network lexicon** — A lexicon fetched directly from the AT Protocol network via DNS authority resolution, rather than uploaded manually. See [Lexicons - Network lexicons](../guides/lexicons.md#network-lexicons).

**Tap** — A [firehose consumer and backfill worker](https://github.com/bluesky-social/indigo/tree/main/cmd/tap) that handles real-time record streaming, cryptographic verification, and historical record fetching. HappyView connects to Tap via WebSocket to receive record events, and delegates backfill work to Tap via its HTTP API.

**Target collection** — The record collection that a query or procedure lexicon operates on. Set via the `target_collection` field when uploading a lexicon.
