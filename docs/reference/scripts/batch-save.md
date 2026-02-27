# Procedure: Batch Save

Use `Record.save_all()` to create multiple records in parallel.

**Lexicon type:** procedure

```lua
function handle()
  local records = {}
  for _, item in ipairs(input.items) do
    local r = Record(collection, item)
    records[#records + 1] = r
  end
  Record.save_all(records)

  local uris = {}
  for _, r in ipairs(records) do
    uris[#uris + 1] = r._uri
  end
  return { uris = uris }
end
```

## How it works

1. Iterate over `input.items` and create a [`Record`](../../guides/scripting.md#record-api) instance for each item.
2. Call [`Record.save_all()`](../../guides/scripting.md#static-methods) to save all records in parallel, rather than one at a time.
3. Collect the resulting AT URIs and return them.

## Usage

```sh
curl -X POST http://localhost:3000/xrpc/xyz.statusphere.batchCreate \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "items": [
      { "text": "First", "createdAt": "2025-01-01T00:00:00Z" },
      { "text": "Second", "createdAt": "2025-01-01T00:01:00Z" }
    ]
  }'
```

## Use case

Batch saving is useful when a single user action should create multiple records (e.g. importing data, multi-step forms). `save_all` is significantly faster than calling `r:save()` in a loop because the PDS writes happen concurrently.
