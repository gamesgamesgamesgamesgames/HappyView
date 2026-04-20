# Tutorial: Statusphere with HappyView

[Statusphere](https://github.com/bluesky-social/statusphere-example-app) is an example atproto application where users set their current status as a single emoji. It's a great way to learn how HappyView works because the data model is simple but the queries are interesting.

In this tutorial, you'll set up HappyView to act as the AppView for Statusphere. By the end, you'll have indexed records and working XRPC endpoints.

:::tip
This tutorial assumes you have a running HappyView instance. If you don't, start with the [Quickstart](../getting-started/deployment/railway.md) or one of the local development guides ([Docker](../getting-started/deployment/docker.md), [from source](../getting-started/deployment/other.md)).
:::

## The Statusphere lexicon

Statusphere uses a single record type, `xyz.statusphere.status`. Each record has two fields:

- `status`: a single emoji
- `createdAt`: a timestamp

Users can set their status as many times as they want. Each status is a new record in their repository, keyed by a TID (timestamp-based identifier). The most recent record is their "current" status.

For more background on how the app works, see the [ATProto Statusphere guide](https://atproto.com/guides/applications).

## Step 1: Add the record lexicon

First, tell HappyView to start indexing Statusphere records. Since `xyz.statusphere.status` is [published on the atproto network](../guides/lexicons.md#network-lexicons), you can add it directly from the dashboard:

1. Go to **Lexicons > Add Lexicon > Network**
2. Enter `xyz.statusphere.status`
3. HappyView resolves the schema from its authority domain records and shows a preview
4. Enable the **Backfill** toggle so HappyView fetches existing records from the network
5. Click **Add**

HappyView now subscribes to `xyz.statusphere.status` via Jetstream and kicks off a backfill job to index historical records.

:::tip
You can also add lexicons via the [admin API](../reference/admin/lexicons.md). This is useful for automation or CI/CD workflows:

```sh
curl -X POST http://localhost:3000/admin/lexicons \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "lexicon_json": {
      "lexicon": 1,
      "id": "xyz.statusphere.status",
      "defs": {
        "main": {
          "type": "record",
          "key": "tid",
          "record": {
            "type": "object",
            "required": ["status", "createdAt"],
            "properties": {
              "status": { "type": "string", "maxGraphemes": 1 },
              "createdAt": { "type": "string", "format": "datetime" }
            }
          }
        }
      }
    },
    "backfill": true
  }'
```

:::

## Step 2: Verify records are being indexed

Once the backfill starts, you should see records appearing in the dashboard:

1. The **home page** shows a live record count and per-collection breakdown
2. Go to **Records** to browse individual indexed statuses
3. Go to **Backfill** to watch the backfill job progress — you'll see the number of repos processed and records fetched

## Step 3: Add a query lexicon for listing statuses

Now add a query endpoint to read the indexed data:

1. Go to **Lexicons > Add Lexicon > Local**
2. Set the NSID to `xyz.statusphere.listStatuses`
3. Set the type to **Query**
4. Set `target_collection` to `xyz.statusphere.status` — this tells the query which record collection it operates on (`target_collection` is a HappyView-specific field, not part of the lexicon spec)
5. Click **Add**

This creates a `GET /xrpc/xyz.statusphere.listStatuses` endpoint. Without a Lua script, it uses HappyView's built-in default behavior: listing records with `limit`, `cursor`, and `did` parameters, or fetching a single record by `uri`. Try it:

```sh
curl "http://localhost:3000/xrpc/xyz.statusphere.listStatuses?limit=5" \
  -H "X-Client-Key: $CLIENT_KEY"
```

```json
{
  "records": [
    {
      "uri": "at://did:plc:abc/xyz.statusphere.status/3abc123",
      "status": "\ud83d\ude0a",
      "createdAt": "2025-01-01T12:00:00Z"
    },
    {
      "uri": "at://did:plc:def/xyz.statusphere.status/3def456",
      "status": "\ud83c\udf1f",
      "createdAt": "2025-01-01T11:30:00Z"
    }
  ],
  "cursor": "MjAyNS0wMS0wMVQxMjowMDowMFp8YXQ6Ly9kaWQ6..."
}
```

See [XRPC API](../reference/xrpc-api.md) for the full default query behavior.

## Step 4: Enhance the query with a Lua script

The default query behavior works, but let's customize it with a [Lua script](../guides/scripting.md). The script will handle single-record lookups by URI and paginated listing with an optional DID filter.

1. Click on **xyz.statusphere.listStatuses** in the lexicon list to open its detail page
2. The Lua script editor is at the bottom of the page
3. Paste in the following script:

```lua
function handle()
  if params.uri then
    local record = db.get(params.uri)
    if not record then
      return { error = "not found" }
    end
    return { record = record }
  end

  return db.query({
    collection = collection,
    did = params.did,
    limit = tonumber(params.limit) or 20,
    cursor = params.cursor,
  })
end
```

4. Click **Save**

The endpoint now uses your custom logic. Filter by a specific user:

```sh
curl "http://localhost:3000/xrpc/xyz.statusphere.listStatuses?did=did:plc:abc&limit=1" \
  -H "X-Client-Key: $CLIENT_KEY"
```

Fetch a single record by URI:

```sh
curl "http://localhost:3000/xrpc/xyz.statusphere.listStatuses?uri=at://did:plc:abc/xyz.statusphere.status/3abc123" \
  -H "X-Client-Key: $CLIENT_KEY"
```

## Step 5: Add a procedure lexicon for setting status

Add a write endpoint so users can set their status through your AppView:

1. Go to **Lexicons > Add Lexicon > Local**
2. Set the NSID to `xyz.statusphere.setStatus`
3. Set the type to **Procedure**
4. Set `target_collection` to `xyz.statusphere.status`
5. A default Lua script is generated — replace it with:

```lua
function handle()
  local r = Record(collection, {
    status = input.status,
    createdAt = now(),
  })
  r:save()
  return { uri = r._uri, cid = r._cid }
end
```

6. Click **Add**

This creates a `POST /xrpc/xyz.statusphere.setStatus` endpoint that creates records on the user's PDS and indexes them locally.

## Step 6: Test the procedure endpoint

Set a status. This requires DPoP authentication — the [JavaScript SDK](../sdk/overview.md) handles this for you, but you can test with curl if you have a token:

```sh
curl -X POST http://localhost:3000/xrpc/xyz.statusphere.setStatus \
  -H "X-Client-Key: $CLIENT_KEY" \
  -H "Authorization: DPoP $TOKEN" \
  -H "DPoP: $DPOP_PROOF" \
  -H "Content-Type: application/json" \
  -d '{ "status": "\ud83d\ude80" }'
```

```json
{
  "uri": "at://did:plc:yourDID/xyz.statusphere.status/3xyz789",
  "cid": "bafyreiabc123..."
}
```

The record is created on your PDS and immediately indexed by HappyView.

## What you've built

With three lexicons and a few lines of Lua, you have a complete Statusphere AppView:

- **Real-time indexing** of `xyz.statusphere.status` records from the entire atproto network
- **Historical backfill** of existing status records
- **A query endpoint** (`xyz.statusphere.listStatuses`) with filtering, pagination, and single-record lookups
- **A write endpoint** (`xyz.statusphere.setStatus`) that creates records on the user's PDS and indexes them locally

Everything was done through the dashboard — no server restarts, no config files, no deploys. For automation and CI/CD, the same operations are available via the [admin API](../reference/admin-api.md).

## Next steps

- [Lua Scripting](../guides/scripting.md): Explore the full Record and database APIs to build more complex queries
- [Lexicons](../guides/lexicons.md): Learn about network lexicons, the backfill flag, and target collections
- [XRPC API](../reference/xrpc-api.md): Understand how the generated endpoints behave
- [Admin API](../reference/admin-api.md): Automate lexicon management via the API
- [Statusphere example app](https://github.com/bluesky-social/statusphere-example-app): See the full Statusphere frontend
- [ATProto Statusphere guide](https://atproto.com/guides/applications): Deep dive into how the app works at the protocol level
