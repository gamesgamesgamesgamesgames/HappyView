# Query: Paginated List

List records from a collection with cursor-based pagination and an optional DID filter.

**Lexicon type:** query

```lua
function handle()
  local limit = tonumber(params.limit) or 20
  if limit > 100 then limit = 100 end

  local result = db.query({
    collection = collection,
    did = params.did,
    limit = limit,
    cursor = params.cursor,
  })

  return result
end
```

## How it works

1. Parse `limit` from the query string, defaulting to 20 and capping at 100.
2. Call [`db.query`](../../reference/lua/database-api.md#dbquery) with the target collection, optional DID filter, and cursor for pagination.
3. Return the result directly. `db.query` returns `{ records = [...], cursor = "..." }` where `cursor` is an opaque string present when more records exist.

## Usage

```
GET /xrpc/xyz.statusphere.listStatuses
GET /xrpc/xyz.statusphere.listStatuses?limit=50
GET /xrpc/xyz.statusphere.listStatuses?did=did:plc:abc&limit=10
GET /xrpc/xyz.statusphere.listStatuses?cursor=<opaque>&limit=20
```

## Use case

A list endpoint for feeds, timelines, or browsing records by collection. The `cursor` value returned by `db.query` is an opaque string. Clients pass it back as the `cursor` parameter to fetch the next page — don't parse or modify it.
