# Query: Get a Single Record

Fetch a single record by its AT URI.

**Lexicon type:** query

```lua
function handle()
  if not params.uri then
    return { error = "uri parameter is required" }
  end

  local record = db.get(params.uri)
  if not record then
    return { error = "not found" }
  end

  return { record = record }
end
```

## How it works

1. Check that the `uri` query parameter is present. Return a structured error if missing.
2. Look up the record with [`db.get`](../../guides/scripting#dbget), which returns the record table or `nil`.
3. Return the record wrapped in an object.

## Usage

```
GET /xrpc/xyz.statusphere.getRecord?uri=at://did:plc:abc/xyz.statusphere.record/abc123
```

## Use case

A focused read endpoint for detail views or record verification. Returns structured error responses instead of calling `error()`, so the client gets a 200 with an error field it can handle gracefully rather than a 500.
