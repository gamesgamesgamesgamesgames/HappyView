# Procedure: Upsert a Record

Create a new record, or update an existing one if the client provides its rkey.

**Lexicon type:** procedure

```lua
function handle()
  local rkey = input.rkey or TID()
  local uri = "at://" .. caller_did .. "/" .. collection .. "/" .. rkey

  local r = Record.load(uri)
  if r then
    -- Update existing record
    r.status = input.status
    r.updatedAt = now()
    r:save()
  else
    -- Create new record
    r = Record(collection, {
      status = input.status,
      createdAt = now(),
      updatedAt = now(),
    })
    r:set_rkey(rkey)
    r:save()
  end

  return { uri = r._uri, cid = r._cid }
end
```

## How it works

1. Use the client-provided `input.rkey` if present, otherwise generate a new [`TID()`](../../guides/scripting#utility-globals). This means omitting `rkey` always creates, while providing one enables updates.
2. Build the AT URI from the caller's DID, the target collection, and the rkey, then try to load it with [`Record.load`](../../guides/scripting#static-methods).
3. If the record exists, update its fields and save. Since `_uri` is already set, `r:save()` calls `putRecord`.
4. If it doesn't exist, create a new record, set the rkey explicitly with `r:set_rkey()`, and save. This calls `createRecord` with the specified rkey.

## Usage

```sh
# Create: no rkey, so a new TID is generated
curl -X POST http://localhost:3000/xrpc/xyz.statusphere.setStatus \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{ "status": "hello" }'
# → { "uri": "at://did:plc:abc/xyz.statusphere.status/3abc123", "cid": "bafyrei..." }

# Update: pass the rkey back to update the same record
curl -X POST http://localhost:3000/xrpc/xyz.statusphere.setStatus \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{ "rkey": "3abc123", "status": "updated" }'
# → { "uri": "at://did:plc:abc/xyz.statusphere.status/3abc123", "cid": "bafyrei..." }
```

## Use case

This is useful when the client knows whether it's creating or editing, but you want a single endpoint for both. The client omits `rkey` for new records and includes it when editing an existing one. The rkey from the initial create response acts as the record's stable identifier for future updates.
