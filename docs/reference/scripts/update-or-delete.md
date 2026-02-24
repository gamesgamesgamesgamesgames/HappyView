# Procedure: Update or Delete

A single endpoint that handles create, update, and delete based on the input fields.

**Lexicon type:** procedure

```lua
function handle()
  if input.delete and input.uri then
    local r = Record.load(input.uri)
    if r then r:delete() end
    return { success = true }
  end

  if input.uri then
    -- Update existing
    local r = Record.load(input.uri)
    if not r then error("not found") end
    r.status = input.status
    r:save()
    return { uri = r._uri, cid = r._cid }
  end

  -- Create new
  local r = Record(collection, input)
  r:save()
  return { uri = r._uri, cid = r._cid }
end
```

## How it works

1. If `input.delete` is truthy and `input.uri` is provided, load the record with [`Record.load`](../../guides/scripting#static-methods) and delete it.
2. If only `input.uri` is provided, load the existing record with [`Record.load`](../../guides/scripting#static-methods), update its fields, and save it back. Since `_uri` is already set, `r:save()` calls `putRecord` instead of `createRecord`.
3. If neither condition matches, create a new record from the input.

## Usage

```sh
# Create
curl -X POST http://localhost:3000/xrpc/xyz.statusphere.setRecord \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{ "status": "hello" }'

# Update
curl -X POST http://localhost:3000/xrpc/xyz.statusphere.setRecord \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{ "uri": "at://did:plc:abc/xyz.statusphere.record/abc123", "status": "updated" }'

# Delete
curl -X POST http://localhost:3000/xrpc/xyz.statusphere.setRecord \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{ "uri": "at://did:plc:abc/xyz.statusphere.record/abc123", "delete": true }'
```

## Use case

This pattern reduces the number of endpoints your app needs by multiplexing create, update, and delete through a single procedure. The presence of `uri` and `delete` fields in the input determines the action.
