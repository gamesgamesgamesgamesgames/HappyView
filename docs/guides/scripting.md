# Lua Scripting

Without Lua scripts, HappyView's query endpoints return raw records and procedure endpoints proxy simple creates and updates. Lua scripts let you go much further:

- Add filtering logic
- Transform responses
- Validate input
- Compose multi-record operations
- Build entirely custom behavior

Scripts are attached to query and procedure lexicons and run in a sandboxed Lua VM with access to the [Record API](#record-api), a [read-only database API](#database-api), and a set of [context globals](#context-globals).

## Script structure

Every script must define a `handle()` function. HappyView calls it when the XRPC endpoint is hit and returns its result as JSON to the client.

```lua
function handle()
  -- your logic here
  return { key = "value" }
end
```

You can define helper functions and variables outside `handle()`. They're evaluated once when the script loads, then `handle()` is called per request.

## Sandbox

Scripts run in a restricted environment. The following standard Lua modules are **removed** and unavailable:

`os`, `io`, `debug`, `package`, `require`, `dofile`, `loadfile`, `load`, `collectgarbage`

An instruction limit of 1,000,000 prevents infinite loops. Exceeding it terminates the script with an error.

## Context globals

These globals are set automatically before `handle()` is called.

### Procedure globals

| Global       | Type   | Description                                             |
| ------------ | ------ | ------------------------------------------------------- |
| `method`     | string | The XRPC method name (e.g. `xyz.statusphere.setStatus`) |
| `input`      | table  | Parsed JSON request body                                |
| `caller_did` | string | DID of the authenticated user                           |
| `collection` | string | Target collection NSID                                  |

### Query globals

| Global       | Type   | Description                                      |
| ------------ | ------ | ------------------------------------------------ |
| `method`     | string | The XRPC method name                             |
| `params`     | table  | Query string parameters (all values are strings) |
| `collection` | string | Target collection NSID                           |

Queries are unauthenticated: there is no `caller_did` or `input`.

## Utility globals

Available in both queries and procedures:

| Function         | Returns | Description                                                         |
| ---------------- | ------- | ------------------------------------------------------------------- |
| `now()`          | string  | Current UTC timestamp in ISO 8601 format                            |
| `log(message)`   | —       | Log a message (appears in server logs at debug level)               |
| `TID()`          | string  | Generate a fresh AT Protocol TID (13-character sortable identifier) |
| `toarray(table)` | table   | Mark a table as a JSON array for serialization (see [below](#toarray)) |

### toarray

Lua tables don't distinguish between arrays and objects. When a table is serialized to JSON, an empty table `{}` becomes a JSON object `{}` instead of an array `[]`. The `toarray()` function marks a table so it always serializes as a JSON array — even when empty.

```lua
return { items = toarray(results) }
-- With results: [{"name": "a"}, {"name": "b"}]
-- Without results: {"items": []}   (not {"items": {}})
```

You don't need `toarray()` on results from `db.query`, `db.search`, `db.backlinks`, or `db.raw` — those already return properly marked arrays. Use it when you build a table yourself with `table.insert()`.

## Record API

The `Record` API is only available in **procedure** scripts. It handles creating, updating, loading, and deleting AT Protocol records. Writes are proxied to the caller's PDS and indexed locally.

### Constructor

```lua
local r = Record("xyz.statusphere.status", { status = "\ud83d\ude0a", createdAt = now() })
```

Creates a new record instance for the given collection. The optional second argument sets initial field values. The record's `_key_type` is automatically set from the lexicon's `key` definition. Default values from the schema are populated for any missing fields.

### Static methods

```lua
-- Save multiple records in parallel
Record.save_all({ record1, record2, record3 })

-- Load a record from the local database by AT URI
local r = Record.load("at://did:plc:abc/xyz.statusphere.status/abc123")
-- Returns nil if not found

-- Load multiple records in parallel
local records = Record.load_all({ uri1, uri2 })
-- Returns nil entries for URIs not found
```

### Instance methods

```lua
-- Save (creates or updates depending on whether _uri is set)
r:save()

-- Delete from PDS and local database
r:delete()

-- Set the record key type (tid, any, nsid, or literal:*)
r:set_key_type("tid")

-- Set a specific record key
r:set_rkey("my-key")

-- Auto-generate a record key based on _key_type
local key = r:generate_rkey()
```

**Key type behavior for `generate_rkey()`:**

| Key type        | Generated rkey                    |
| --------------- | --------------------------------- |
| `tid`           | Sortable timestamp-based ID       |
| `any`           | Same as `tid`                     |
| `literal:value` | The literal value after the colon |
| `nsid`          | Error — use `set_rkey()` instead  |

### Instance fields

These fields are set automatically and are read-only (writes raise an error):

| Field         | Type    | Description                                                 |
| ------------- | ------- | ----------------------------------------------------------- |
| `_uri`        | string? | AT URI — set after `save()`, cleared after `delete()`       |
| `_cid`        | string? | Content hash — set after `save()`, cleared after `delete()` |
| `_key_type`   | string? | Record key type from the lexicon definition                 |
| `_rkey`       | string? | Record key — set via `set_rkey()` or `generate_rkey()`      |
| `_collection` | string  | Collection NSID (always set)                                |
| `_schema`     | table?  | Schema definition from the lexicon (used for validation)    |

### Schema validation

When a record has a schema (loaded from the lexicon):

- **On save:** required fields are checked, and missing required fields raise an error
- **On construction:** default values from schema properties are auto-populated
- **On save:** only fields defined in the schema's `properties` are sent to the PDS

### Save behavior

`r:save()` auto-detects create vs update:

- If `_uri` is nil → calls `createRecord` on the PDS
- If `_uri` is set → calls `putRecord` on the PDS

After a successful save, `_uri` and `_cid` are updated on the record instance.

## Database API

The `db` table provides read-only access to indexed records. Available in both queries and procedures.

### db.query

```lua
local result = db.query({
  collection = "xyz.statusphere.status",  -- required
  did = "did:plc:abc",                    -- optional: filter by DID
  limit = 20,                             -- optional: max 100, default 20
  offset = 0,                             -- optional: for pagination
})

-- result.records — array of record tables (each includes a "uri" field)
-- result.cursor — present when more records exist
```

### db.get

```lua
local record = db.get("at://did:plc:abc/xyz.statusphere.status/abc123")
-- Returns the record table or nil
-- The returned table includes a "uri" field
```

### db.search

```lua
local result = db.search({
  collection = "xyz.statusphere.status",  -- required
  field = "displayName",                  -- required: record field to search
  query = "alice",                        -- required: search term
  limit = 10,                             -- optional: max 100, default 10
})

-- result.records — array of matching records, ranked by relevance:
--   exact match > prefix match > contains match, then alphabetical
```

### db.backlinks

Find records that reference a given AT URI anywhere in their data. Useful for finding likes on a post, replies to a thread, or any record that links to another.

```lua
local result = db.backlinks({
  collection = "xyz.statusphere.status",                -- required
  uri = "at://did:plc:abc/xyz.statusphere.status/foo",  -- required: the URI to find references to
  did = "did:plc:abc",                                  -- optional: filter by DID
  limit = 20,                                           -- optional: max 100, default 20
  offset = 0,                                           -- optional: for pagination
})

-- result.records — array of records whose data contains the given URI
-- result.cursor — present when more records exist
```

The search checks the full record data, so it works regardless of which field holds the reference (`subject`, `parent`, `reply.root`, etc.).

### db.count

```lua
local n = db.count("xyz.statusphere.status")
local n = db.count("xyz.statusphere.status", "did:plc:abc")  -- filter by DID
```

### db.raw

Run a raw SQL query against the database. Only `SELECT` statements are allowed.

```lua
local rows = db.raw(
  "SELECT uri, did, record FROM records WHERE collection = $1 AND did = $2 LIMIT $3",
  { "xyz.statusphere.status", "did:plc:abc", 10 }
)

for _, row in ipairs(rows) do
  -- row.uri, row.did, row.record (JSONB is returned as a Lua table)
end
```

Parameters are passed as an array and bound to `$1`, `$2`, etc. Supported parameter types: strings, integers, numbers, booleans, and nil.

Column types are mapped automatically:

| Postgres type          | Lua type |
| ---------------------- | -------- |
| `TEXT`, `VARCHAR`      | string   |
| `INT4`, `INT8`         | integer  |
| `FLOAT4`, `FLOAT8`     | number   |
| `BOOL`                 | boolean  |
| `JSON`, `JSONB`        | table    |
| `TIMESTAMPTZ`          | string (ISO 8601) |
| Other                  | string (fallback)  |

## Standard libraries

The following Lua 5.4 standard library modules are available:

<details>
<summary>
`string`
</summary>
- [`byte`](https://lua.org/manual/5.4/manual.html#pdf-string.byte)
- [`char`](https://lua.org/manual/5.4/manual.html#pdf-string.char)
- [`find`](https://lua.org/manual/5.4/manual.html#pdf-string.find)
- [`format`](https://lua.org/manual/5.4/manual.html#pdf-string.format)
- [`gmatch`](https://lua.org/manual/5.4/manual.html#pdf-string.gmatch)
- [`gsub`](https://lua.org/manual/5.4/manual.html#pdf-string.gsub)
- [`len`](https://lua.org/manual/5.4/manual.html#pdf-string.len)
- [`lower`](https://lua.org/manual/5.4/manual.html#pdf-string.lower)
- [`match`](https://lua.org/manual/5.4/manual.html#pdf-string.match)
- [`rep`](https://lua.org/manual/5.4/manual.html#pdf-string.rep)
- [`reverse`](https://lua.org/manual/5.4/manual.html#pdf-string.reverse)
- [`sub`](https://lua.org/manual/5.4/manual.html#pdf-string.sub)
- [`upper`](https://lua.org/manual/5.4/manual.html#pdf-string.upper)
</details>

<details>
<summary>
`table`
</summary>
- [`concat`](https://lua.org/manual/5.4/manual.html#pdf-table.concat)
- [`insert`](https://lua.org/manual/5.4/manual.html#pdf-table.insert)
- [`remove`](https://lua.org/manual/5.4/manual.html#pdf-table.remove)
- [`sort`](https://lua.org/manual/5.4/manual.html#pdf-table.sort)
- [`unpack`](https://lua.org/manual/5.4/manual.html#pdf-table.unpack)
</details>

<details>
<summary>
`math`
</summary>
- [`abs`](https://lua.org/manual/5.4/manual.html#pdf-math.abs)
- [`ceil`](https://lua.org/manual/5.4/manual.html#pdf-math.ceil)
- [`floor`](https://lua.org/manual/5.4/manual.html#pdf-math.floor)
- [`max`](https://lua.org/manual/5.4/manual.html#pdf-math.max)
- [`min`](https://lua.org/manual/5.4/manual.html#pdf-math.min)
- [`random`](https://lua.org/manual/5.4/manual.html#pdf-math.random)
- [`sqrt`](https://lua.org/manual/5.4/manual.html#pdf-math.sqrt)
- [`huge`](https://lua.org/manual/5.4/manual.html#pdf-math.huge)
- [`pi`](https://lua.org/manual/5.4/manual.html#pdf-math.pi)
</details>

<details>
<summary>
Standard builtins
</summary>
- [`print`](https://lua.org/manual/5.4/manual.html#pdf-print)
- [`tostring`](https://lua.org/manual/5.4/manual.html#pdf-tostring)
- [`tonumber`](https://lua.org/manual/5.4/manual.html#pdf-tonumber)
- [`type`](https://lua.org/manual/5.4/manual.html#pdf-type)
- [`pairs`](https://lua.org/manual/5.4/manual.html#pdf-pairs)
- [`ipairs`](https://lua.org/manual/5.4/manual.html#pdf-ipairs)
- [`next`](https://lua.org/manual/5.4/manual.html#pdf-next)
- [`select`](https://lua.org/manual/5.4/manual.html#pdf-select)
- [`unpack`](https://lua.org/manual/5.4/manual.html#pdf-table.unpack)
- [`error`](https://lua.org/manual/5.4/manual.html#pdf-error)
- [`pcall`](https://lua.org/manual/5.4/manual.html#pdf-pcall)
- [`xpcall`](https://lua.org/manual/5.4/manual.html#pdf-xpcall)
- [`assert`](https://lua.org/manual/5.4/manual.html#pdf-assert)
- [`setmetatable`](https://lua.org/manual/5.4/manual.html#pdf-setmetatable)
- [`getmetatable`](https://lua.org/manual/5.4/manual.html#pdf-getmetatable)
- [`rawget`](https://lua.org/manual/5.4/manual.html#pdf-rawget)
- [`rawset`](https://lua.org/manual/5.4/manual.html#pdf-rawset)
- [`rawequal`](https://lua.org/manual/5.4/manual.html#pdf-rawequal)
</details>

## Debugging

### Logging

Use `log()` to trace script execution. Output appears in the server logs at **debug** level with the field `lua_log`:

```lua
function handle()
  log("handle called with params: " .. tostring(params.limit))
  local result = db.query({ collection = collection, limit = params.limit })
  log("query returned " .. #result.records .. " records")
  return result
end
```

To see log output, make sure your `RUST_LOG` environment variable includes debug level for HappyView (the default `happyview=debug` works). See [Configuration](../getting-started/configuration.md).

### Error messages

When a script fails, the client receives a generic `500` response:

- `{"error": "script execution failed"}`: covers syntax errors, runtime errors, missing `handle()` function, and errors raised with `error()`
- `{"error": "script exceeded execution time limit"}`: the script hit the 1,000,000 instruction limit

The **full error message** is logged server-side at error level. Check the server logs to see the actual Lua error, including line numbers and stack traces.

### Common mistakes

- **Missing `handle()` function**: Every script must define a global `handle()` function. If it's missing or misspelled, the script fails silently with "script execution failed".
- **Calling `error()` for expected conditions**: Lua's `error()` triggers a 500 response. For expected conditions like "record not found", return a structured error response instead: `return { error = "not found" }`.
- **Infinite loops**: The sandbox enforces a 1,000,000 instruction limit. If your script processes large data sets, paginate with `db.query()` limits instead of loading everything at once.
- **Forgetting `params` values are strings**: All query string parameters arrive as strings. Use `tonumber(params.limit)` if you need a number.

## Example scripts

See the example script references for complete, ready-to-use scripts:

**Queries:**
- [Get a record](../reference/scripts/get-record.md) — fetch a single record by AT URI
- [Paginated list](../reference/scripts/paginated-list.md) — list records with cursor-based pagination and DID filtering
- [List or fetch](../reference/scripts/list-or-fetch.md) — combined single-record lookup and paginated listing
- [Expanded query](../reference/scripts/expanded-query.md) — list statuses with user profiles in a single response

**Procedures:**
- [Create a record](../reference/scripts/create-record.md) — simple write that saves input as a record
- [Upsert a record](../reference/scripts/upsert-record.md) — create or update using a deterministic rkey
- [Update or delete](../reference/scripts/update-or-delete.md) — single endpoint handling create, update, and delete
- [Batch save](../reference/scripts/batch-save.md) — create multiple records in parallel with `Record.save_all()`
- [Sidecar records](../reference/scripts/sidecar-records.md) — create linked records across collections with a shared rkey
- [Cascading delete](../reference/scripts/cascading-delete.md) — delete a record and all related records
- [Complex mutations](../reference/scripts/complex-mutations.md) — load, transform, and save a record with multiple field changes

## Next steps

- [Lexicons](lexicons.md): Understand how record, query, and procedure lexicons work together
- [XRPC API](../reference/xrpc-api.md): See how endpoints behave with and without Lua scripts
- [Dashboard](../getting-started/dashboard.md#lua-editor): Use the web editor with context-aware completions
