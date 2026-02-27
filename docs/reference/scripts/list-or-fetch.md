# Query: List or Fetch Records

This query handles both single-record lookups (when a `uri` param is provided) and paginated listing.

**Lexicon type:** query

```lua
function handle()
  if params.uri then
    local record = db.get(params.uri)
    if not record then
      return { error = "record not found" }
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

## How it works

1. If a `uri` query parameter is provided, fetch that single record with [`db.get`](../../guides/scripting.md#dbget) and return it. If it doesn't exist, return a structured error (using `error()` would trigger a 500 response).
2. Otherwise, list records from the target collection using [`db.query`](../../guides/scripting.md#dbquery), with optional filtering by `did` and pagination via `limit`/`offset`. Since query parameters arrive as strings, `tonumber()` converts them to numbers.

## Usage

```
GET /xrpc/xyz.statusphere.listRecords?limit=10
GET /xrpc/xyz.statusphere.listRecords?did=did:plc:abc
GET /xrpc/xyz.statusphere.listRecords?uri=at://did:plc:abc/xyz.statusphere.record/abc123
```

## Use case

This is a good default query script when you want a single endpoint that serves double duty: list browsing for feeds/timelines and direct record fetching for detail views.
