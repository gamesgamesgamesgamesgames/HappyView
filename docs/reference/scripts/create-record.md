# Procedure: Create a Record

The simplest write: take the request body, save it as a record, and return the URI.

**Lexicon type:** procedure

```lua
function handle()
  local r = Record(collection, input)
  r:save()
  return { uri = r._uri, cid = r._cid }
end
```

## How it works

1. Create a new [`Record`](../../guides/scripting#record-api) instance from the target collection, populated with the fields from the request body.
2. Call `r:save()`, which creates the record on the caller's PDS and indexes it locally.
3. Return the AT URI and CID of the newly created record.

## Usage

```sh
curl -X POST http://localhost:3000/xrpc/xyz.statusphere.createRecord \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{ "text": "Hello world", "createdAt": "2025-01-01T00:00:00Z" }'
```

## Use case

This is the simplest possible write procedure. It works well when the client is responsible for populating all record fields and no server-side validation or transformation is needed.
