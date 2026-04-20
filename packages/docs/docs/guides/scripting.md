# Lua Scripting

Without Lua scripts, HappyView's query endpoints return raw records and procedure endpoints proxy simple creates and updates. Lua scripts let you go much further:

- Add filtering logic
- Transform responses
- Validate input
- Compose multi-record operations
- Build entirely custom behavior

Scripts are attached to query and procedure lexicons and run in a sandboxed Lua VM with access to the [Record API](#record-api), a [database API](#database-api), an [HTTP client API](#http-api), a [JSON API](#json-api), and a set of [context globals](#context-globals).

For scripts that react to record changes from the network (rather than XRPC requests), see [Index Hooks](index-hooks.md).

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

`io`, `debug`, `package`, `require`, `dofile`, `loadfile`, `load`, `collectgarbage`

The `os` module is replaced with a safe subset exposing only `os.time`, `os.date`, `os.difftime`, and `os.clock`. Dangerous functions like `os.execute`, `os.remove`, `os.rename`, and `os.exit` are not available.

An instruction limit of 1,000,000 prevents infinite loops. Exceeding it terminates the script with an error.

See the [Standard Libraries](../reference/lua/standard-libraries.md) reference for the full list of available Lua modules and builtins.

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
| `TID()`          | string  | Generate a fresh atproto TID (13-character sortable identifier) |
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

The `Record` API is only available in **procedure** scripts. It handles creating, updating, loading, and deleting atproto records. Writes are proxied to the caller's PDS and indexed locally.

See the full [Record API reference](../reference/lua/record-api.md) for constructor, static methods, instance methods, fields, schema validation, and save behavior.

Quick example:

```lua
function handle()
  local r = Record(collection, input)
  r:save()
  return { uri = r._uri, cid = r._cid }
end
```

## Database API

The `db` table provides access to the database. Available in both queries and procedures.

See the full [Database API reference](../reference/lua/database-api.md) for `db.query`, `db.get`, `db.search`, `db.backlinks`, `db.count`, and `db.raw`.

Quick example:

```lua
function handle()
  local result = db.query({ collection = collection, limit = 20 })
  return { records = result.records, cursor = result.cursor }
end
```

## HTTP API

The `http` table provides async HTTP client functions. Available in both queries and procedures.

See the full [HTTP API reference](../reference/lua/http-api.md) for all methods, options, and response format.

Quick example:

```lua
local resp = http.get("https://api.example.com/data")
local data = json.decode(resp.body)
```

## atproto API

The `atproto` table provides atproto utility functions like DID resolution and label queries.

See the full [atproto API reference](../reference/lua/atproto-api.md) for `atproto.resolve_service_endpoint`, `atproto.get_labels`, and `atproto.get_labels_batch`.

## JSON API

The `json` global provides JSON serialization and deserialization.

See the full [JSON API reference](../reference/lua/json-api.md) for `json.encode` and `json.decode`.

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

**Index Hooks:**
- [Algolia sync](../reference/scripts/algolia-sync.md) — push records to an Algolia search index on create/update/delete

## Next steps

- [Index Hooks](index-hooks.md): React to record changes from the network in real time
- [Lexicons](lexicons.md): Understand how record, query, and procedure lexicons work together
- [XRPC API](../reference/xrpc-api.md): See how endpoints behave with and without Lua scripts
- [Dashboard](../getting-started/dashboard.md#lua-editor): Use the web editor with context-aware completions
