# Lexicons

Lexicons are the core building block of HappyView. They're [AT Protocol schema definitions](https://atproto.com/specs/lexicon) that describe your data model, and HappyView uses them to decide which records to index from the network and what XRPC endpoints to serve.

You don't write route handlers or database queries; you upload a lexicon and HappyView generates the infrastructure from it. There are two ways to add lexicons: uploading them via the [admin API](../reference/admin-api#lexicons) or [dashboard](../getting-started/dashboard), or fetching them directly from the AT Protocol network via [DNS authority resolution](#network-lexicons).

## Supported lexicon types

| Type          | Effect                                                                         |
| ------------- | ------------------------------------------------------------------------------ |
| `record`      | Syncs the collection filter to Tap and indexes records into Postgres           |
| `query`       | Registers a `GET /xrpc/{nsid}` endpoint that queries indexed records           |
| `procedure`   | Registers a `POST /xrpc/{nsid}` endpoint that proxies writes to the user's PDS |
| `definitions` | Stored but does not generate routes or subscriptions                           |

A typical setup has three lexicons working together: a **record** lexicon that defines the data and triggers indexing, a **query** lexicon that exposes a read endpoint, and a **procedure** lexicon that exposes a write endpoint. The [Statusphere tutorial](../tutorials/statusphere) walks through this pattern end-to-end.

## Target collection

Query and procedure lexicons don't store data themselves. They operate on records stored by a record-type lexicon. The `target_collection` field tells HappyView which record collection to read from or write to. Without it, default queries and procedures won't know which DB records to operate on.

For example, a query lexicon `xyz.statusphere.listStatuses` would set `target_collection` to `xyz.statusphere.status` to read from that record collection.

See the [admin API](../reference/admin-api#upload--upsert-a-lexicon) for how to set `target_collection` when uploading.

:::note
The `target_collection` is available in Lua scripts as the `collection` global, but it is not required if your endpoint uses a Lua script.
:::

## Backfill flag

When uploading a record-type lexicon, HappyView automatically creates a backfill job to discover existing records. If you only want to index new records going forward, you can set `backfill` to `false`.

## Tap collection filters

When record-type lexicons change (uploaded or deleted), HappyView automatically syncs the updated collection filter to Tap. HappyView always includes `com.atproto.lexicon.schema` in the filter to track network lexicon updates.

Deleting a lexicon updates Tap's collection filters (stopping live indexing for that collection) but does **not** remove previously indexed repos or their cached state from Tap. To fully reset a collection's state, delete the lexicon, re-add it, and run a [backfill](backfill).

## Network lexicons

If a lexicon has already been published, you don't need to upload the JSON manually. Point HappyView at the NSID and it fetches the lexicon directly from the network. Network lexicons are kept updated automatically via Tap. If the publisher updates their schema, your instance will pick up the change.

### NSID authority resolution

Lexicons are stored as records themselves with the `com.atproto.lexicon.schema` NSID and the rkey set to the lexicon's NSID. To find which repo holds a lexicon, HappyView resolves the NSID's authority:

1. Extract the authority from the NSID (all segments except the last). For example, `xyz.statusphere.status` has authority `xyz.statusphere`.
2. Reverse the authority segments to form a domain: `statusphere.xyz`.
3. Look up the DNS TXT record at `_lexicon.{domain}` (e.g. `_lexicon.statusphere.xyz`).
4. Parse the TXT record for a `did=<DID>` value.
5. Resolve the DID to a PDS endpoint via the PLC directory.

:::note
The spec states that resolution must be **non-hierarchical**. Each authority requires its own explicit TXT record. If you have multiple levels of authority (e.g. `xyz.statusphere.status` and `xyz.statusphere.actor.profile`), each level must have an explicit TXT record.
:::

### Fetching

Once the authority DID and PDS endpoint are known, HappyView calls `com.atproto.repo.getRecord` with:

- `repo` = the authority DID
- `collection` = `com.atproto.lexicon.schema`
- `rkey` = the NSID

The `value` field of the response is the raw lexicon JSON.

### Live updates via Tap

Tap always subscribes to `com.atproto.lexicon.schema` alongside the dynamic record collections. When a record event arrives:

- **create/update**: If the event's DID and rkey match a tracked network lexicon (`authority_did` and `nsid`), the lexicon is parsed, upserted into the `lexicons` table and in-memory registry, and collection filters are updated if it's a record type.
- **delete**: The lexicon is removed from the `lexicons` table and registry.

### Startup re-fetch

On every startup, HappyView re-fetches all network lexicons from their respective PDSes. This ensures consistency even if events were missed while offline. Failures are logged as warnings but don't block startup.

## Next steps

- [Lua Scripting](scripting): Add custom query and procedure logic to your endpoints
- [XRPC API](../reference/xrpc-api): Understand how the generated endpoints behave
- [Backfill](backfill): Learn how historical records are indexed
- [Admin API](../reference/admin-api): Full reference for lexicon management endpoints
