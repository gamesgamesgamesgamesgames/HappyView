# Procedure: Complex Mutations

Load an existing record, apply multiple transformations, and save it back.

**Lexicon type:** procedure

```lua
function handle()
  if not input.uri then
    return { error = "uri is required" }
  end

  local r = Record.load(input.uri)
  if not r then
    return { error = "not found" }
  end

  -- Increment a counter
  r.likeCount = (r.likeCount or 0) + 1

  -- Merge tags, deduplicating and capping at 10
  r.tags = r.tags or {}
  if input.tags then
    for _, tag in ipairs(input.tags) do
      local found = false
      for _, t in ipairs(r.tags) do
        if t == tag then
          found = true
          break
        end
      end
      if not found then
        r.tags[#r.tags + 1] = tag
      end
    end
    -- Keep only the last 10
    while #r.tags > 10 do
      table.remove(r.tags, 1)
    end
  end

  -- Normalize a string field
  if input.title then
    r.title = string.gsub(input.title, "^%s+", "")
    r.title = string.gsub(r.title, "%s+$", "")
  end

  -- Set a computed field
  r.updatedAt = now()

  r:save()

  return { uri = r._uri, cid = r._cid }
end
```

## How it works

1. Load the existing record with [`Record.load`](../../guides/scripting#static-methods). This gives you a mutable `Record` instance with all the current field values.
2. Apply transformations directly on the record's fields:
   - **Increment a counter**: use `or 0` to handle the field being `nil` on first access.
   - **Merge tags**: iterate over `input.tags`, skip duplicates already in `r.tags`, append new ones, then trim the list to 10.
   - **Normalize a string**: use `string.gsub` to trim whitespace.
   - **Set a timestamp**: use [`now()`](../../guides/scripting#utility-globals) for UTC ISO 8601.
3. Call `r:save()`. Since `_uri` is set (from the load), this calls `putRecord` to update the record on the user's PDS.

## Usage

```sh
curl -X POST http://localhost:3000/xrpc/xyz.statusphere.updatePost \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "uri": "at://did:plc:abc/xyz.statusphere.post/abc123",
    "tags": ["tutorial", "atproto"],
    "title": "  My Post Title  "
  }'
```

## Use case

This pattern is useful when updates involve more than simple field replacement: counters, bounded lists, string normalization, or computed fields. All mutations happen in memory before the single `r:save()` call, so there's no partial save: either all changes are written or none are.

If the record has a schema, HappyView only sends fields defined in the schema's `properties` to the PDS on save. Extra fields you set on the record instance are ignored.
