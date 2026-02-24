# Tutorial: Statusphere with HappyView

[Statusphere](https://github.com/bluesky-social/statusphere-example-app) is an example AT Protocol application where users set their current status as a single emoji. It's a great way to learn how HappyView works because the data model is simple but the queries are interesting.

In this tutorial, you'll set up HappyView to act as the AppView for Statusphere. By the end, you'll have automatically indexed records and automatically generated XPRC endpoints.

:::tip
This tutorial assumes you have a running HappyView instance. If you don't, start with the [Quickstart](../getting-started/deployment/railway) or one of the local development guides ([Docker](../getting-started/deployment/docker), [from source](../getting-started/deployment/other)).
:::

## The Statusphere lexicon

Statusphere uses a single record type, `xyz.statusphere.status`. Each record has two fields:

- `status`: a single emoji
- `createdAt`: a timestamp

Users can set their status as many times as they want. Each status is a new record in their repository, keyed by a TID (timestamp-based identifier). The most recent record is their "current" status.

For more background on how the app works, see the [ATProto Statusphere guide](https://atproto.com/guides/applications).

## Step 1: Upload the record lexicon

First, upload the `xyz.statusphere.status` lexicon to HappyView. This tells HappyView to start indexing Statusphere records from across the network as they're created, updated, or deleted.

The examples below use `$TOKEN` as a placeholder for an AIP-issued access token. See [Authentication](../getting-started/authentication) for how to get one.

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

HappyView now subscribes to `xyz.statusphere.status` via Tap. The `backfill` flag tells HappyView to also index existing status records from the network. You can monitor progress with `GET /admin/backfill/status` or the [dashboard](../getting-started/dashboard).

:::tip
Since the `xyz.statusphere.status` lexicon is [published on the AT Protocol network](../guides/lexicons#network-lexicons), you can also add it as a network lexicon instead of uploading the JSON manually:

```sh
curl -X POST http://localhost:3000/admin/network-lexicons \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{ "nsid": "xyz.statusphere.status" }'
```

:::

## Step 2: Verify records are being indexed

Once the backfill starts processing, you should see records appearing. Check the stats:

```sh
curl http://localhost:3000/admin/stats \
  -H "Authorization: Bearer $TOKEN"
```

```json
{
  "total_records": 1234,
  "collections": [{ "collection": "xyz.statusphere.status", "count": 1234 }]
}
```

## Step 3: Add a query lexicon for listing statuses

Now add a query endpoint to read the indexed data. Upload a query lexicon with `target_collection` pointing at the record collection from Step 1:

```sh
curl -X POST http://localhost:3000/admin/lexicons \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "lexicon_json": {
      "lexicon": 1,
      "id": "xyz.statusphere.listStatuses",
      "defs": {
        "main": {
          "type": "query",
          "output": { "encoding": "application/json" }
        }
      }
    },
    "target_collection": "xyz.statusphere.status"
  }'
```

This creates a `GET /xrpc/xyz.statusphere.listStatuses` endpoint. Without a Lua script, it uses HappyView's built-in default behavior: listing records with `limit`, `cursor`, and `did` parameters, or fetching a single record by `uri`. Try it:

```sh
curl "http://localhost:3000/xrpc/xyz.statusphere.listStatuses?limit=5"
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
  "cursor": "5"
}
```

See [XRPC API](../reference/xrpc-api) for the full default query behavior.

## Step 4: Enhance the query with a Lua script

The default query behavior works, but let's customize it with a [Lua script](../guides/scripting). Here's a script that handles single-record lookups by URI and paginated listing with an optional DID filter:

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
    offset = tonumber(params.cursor) or 0,
  })
end
```

Re-upload the lexicon with parameters defined in the schema and the script attached:

```sh
LEXICON='{
  "lexicon": 1,
  "id": "xyz.statusphere.listStatuses",
  "defs": {
    "main": {
      "type": "query",
      "parameters": {
        "type": "params",
        "properties": {
          "uri": { "type": "string" },
          "did": { "type": "string" },
          "limit": { "type": "integer" },
          "cursor": { "type": "string" }
        }
      },
      "output": { "encoding": "application/json" }
    }
  }
}'

SCRIPT='function handle()
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
    offset = tonumber(params.cursor) or 0,
  })
end'

curl -X POST http://localhost:3000/admin/lexicons \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d "{
    \"lexicon_json\": $LEXICON,
    \"target_collection\": \"xyz.statusphere.status\",
    \"script\": \"$SCRIPT\"
  }"
```

The endpoint now uses your custom logic. Filter by a specific user:

```sh
curl "http://localhost:3000/xrpc/xyz.statusphere.listStatuses?did=did:plc:abc&limit=1"
```

Fetch a single record by URI:

```sh
curl "http://localhost:3000/xrpc/xyz.statusphere.listStatuses?uri=at://did:plc:abc/xyz.statusphere.status/3abc123"
```

## Step 5: Add a procedure lexicon for setting status

Add a write endpoint so users can set their status through your AppView. This creates a `POST /xrpc/xyz.statusphere.setStatus` endpoint that proxies writes to the user's PDS.

The Lua script auto-fills `createdAt` and uses the authenticated user's DID:

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

Upload the procedure lexicon with this script:

```sh
LEXICON='{
  "lexicon": 1,
  "id": "xyz.statusphere.setStatus",
  "defs": {
    "main": {
      "type": "procedure",
      "input": { "encoding": "application/json" },
      "output": { "encoding": "application/json" }
    }
  }
}'

SCRIPT='function handle()
  local r = Record(collection, {
    status = input.status,
    createdAt = now(),
  })
  r:save()
  return { uri = r._uri, cid = r._cid }
end'

curl -X POST http://localhost:3000/admin/lexicons \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d "{
    \"lexicon_json\": $LEXICON,
    \"target_collection\": \"xyz.statusphere.status\",
    \"script\": \"$SCRIPT\"
  }"
```

## Step 6: Test the procedure endpoint

Set a status (requires authentication):

```sh
curl -X POST http://localhost:3000/xrpc/xyz.statusphere.setStatus \
  -H "Authorization: Bearer $TOKEN" \
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

With three lexicon uploads and a few lines of Lua, you have a complete Statusphere AppView:

- **Real-time indexing** of `xyz.statusphere.status` records from the entire AT Protocol network
- **Historical backfill** of existing status records
- **A query endpoint** (`xyz.statusphere.listStatuses`) with filtering, pagination, and single-record lookups
- **A write endpoint** (`xyz.statusphere.setStatus`) that creates records on the user's PDS and indexes them locally

## Next steps

- [Lua Scripting](../guides/scripting): Explore the full Record and database APIs to build more complex queries
- [Lexicons](../guides/lexicons): Learn about network lexicons, the backfill flag, and target collections
- [XRPC API](../reference/xrpc-api): Understand how the generated endpoints behave
- [Statusphere example app](https://github.com/bluesky-social/statusphere-example-app): See the full Statusphere frontend
- [ATProto Statusphere guide](https://atproto.com/guides/applications): Deep dive into how the app works at the protocol level
