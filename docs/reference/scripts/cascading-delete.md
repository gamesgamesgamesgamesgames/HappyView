# Procedure: Cascading Delete

Delete a record and all related records across collections.

**Lexicon type:** procedure

```lua
function handle()
  if not input.uri then
    return { error = "uri is required" }
  end

  -- Load the primary record
  local primary = Record.load(input.uri)
  if not primary then
    return { error = "not found" }
  end

  -- Find related records that reference this URI
  local comments = db.query({
    collection = "xyz.statusphere.comment",
    did = caller_did,
    limit = 100,
  })

  -- Collect records to delete
  local to_delete = { primary }
  for _, comment in ipairs(comments.records) do
    if comment.postUri == input.uri then
      local r = Record.load(comment.uri)
      if r then
        to_delete[#to_delete + 1] = r
      end
    end
  end

  -- Delete all matched records
  for _, r in ipairs(to_delete) do
    r:delete()
  end

  return {
    deleted = #to_delete,
  }
end
```

## How it works

1. Load the primary record by URI. Return early if it doesn't exist.
2. Query for related records, in this example comments by the same user that reference the primary record's URI.
3. Load each related record with [`Record.load`](../../guides/scripting#static-methods) to get a deletable `Record` instance.
4. Delete everything. Each `r:delete()` removes the record from the user's PDS and the local index.

## Usage

```sh
curl -X POST http://localhost:3000/xrpc/xyz.statusphere.deletePost \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{ "uri": "at://did:plc:abc/xyz.statusphere.post/abc123" }'
```

```json
{
  "deleted": 4
}
```

## Use case

Cascading deletes are useful when your data model has parent-child relationships across collections. For example, deleting a post should also clean up its comments, reactions, or metadata records. This keeps the user's repo and the local index consistent.

Note that this only deletes records owned by `caller_did`. AT Protocol records can only be deleted by their owner. If the related records could have more than 100 matches, paginate through all of them before deleting.
