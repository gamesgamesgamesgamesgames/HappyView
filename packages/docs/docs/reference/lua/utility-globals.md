# Utility Globals

Global functions available in queries, procedures, and [index hooks](../../guides/indexing/index-hooks.md). These don't belong to a specific API table — they're available at the top level of any Lua script.

## now

```lua
local timestamp = now()
-- "2026-04-19T15:30:00Z"
```

Returns the current UTC time as an ISO 8601 string. Use this for `createdAt`, `updatedAt`, and similar timestamp fields.

## log

```lua
log("processing record: " .. uri)
log("count: " .. tostring(n))
```

Writes a message to the server logs at debug level. Useful for debugging scripts during development. Log output appears in HappyView's stdout — check your platform's log viewer (Railway logs, `docker logs`, terminal output) to see it.

## TID

```lua
local id = TID()
-- "3abc123def456"
```

Generates a fresh atproto TID (Timestamp Identifier) — a 13-character, base32-sortable string derived from the current timestamp. TIDs are the standard record key format in atproto. Use this when creating records with a specific rkey:

```lua
local r = Record(collection, { text = "hello" })
r:set_rkey(TID())
r:save()
```

## toarray

```lua
return { items = toarray(results) }
```

Marks a Lua table so it serializes as a JSON array rather than a JSON object. This matters for empty tables — without `toarray`, an empty `{}` becomes a JSON object `{}` instead of an array `[]`.

```lua
-- Without toarray:
return { items = {} }
-- → {"items": {}}

-- With toarray:
return { items = toarray({}) }
-- → {"items": []}
```

You don't need `toarray()` on results from `db.query`, `db.search`, `db.backlinks`, or `db.raw` — those already return properly marked arrays. Use it when you build a table yourself with `table.insert()` or array-index assignment.
