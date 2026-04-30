# Database API

The `db` table provides access to the database. Available in queries, procedures, and [index hooks](../../guides/indexing/index-hooks.md).

## db.query

```lua
local result = db.query({
  collection = "xyz.statusphere.status",  -- required
  did = "did:plc:abc",                    -- optional: filter by DID
  limit = 20,                             -- optional: max 100, default 20
  cursor = params.cursor,                 -- optional: opaque cursor from a previous response
  sort = "name",                          -- optional: field to sort by, default "indexed_at"
  sortDirection = "asc",                  -- optional: "asc" or "desc", default "desc"
})

-- result.records — array of record tables (each includes a "uri" field)
-- result.cursor — present when more records exist (opaque string, pass back as-is)
```

The `cursor` is an opaque string returned in a previous response. Pass it through directly — don't parse or modify it. When no `sort` field is specified, `db.query` uses keyset pagination (based on `created_at` and `uri`), which is stable even when records are inserted between pages. When a custom `sort` field is specified, offset-based pagination is used instead.

The `sort` field can be a top-level column (`indexed_at`, `did`, `uri`) or any field inside the record's `value` object (e.g. `name`, `createdAt`). Field names must contain only alphanumeric characters and underscores.

## db.get

```lua
local record = db.get("at://did:plc:abc/xyz.statusphere.status/abc123")
-- Returns the record table or nil
-- The returned table includes a "uri" field
```

## db.search

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

## db.backlinks

Find records that reference a given AT URI anywhere in their data. Useful for finding likes on a post, replies to a thread, or any record that links to another.

```lua
local result = db.backlinks({
  collection = "xyz.statusphere.status",                -- required
  uri = "at://did:plc:abc/xyz.statusphere.status/foo",  -- required: the URI to find references to
  did = "did:plc:abc",                                  -- optional: filter by DID
  limit = 20,                                           -- optional: max 100, default 20
  cursor = params.cursor,                               -- optional: opaque cursor from a previous response
})

-- result.records — array of records whose data contains the given URI
-- result.cursor — present when more records exist (opaque string, pass back as-is)
```

The search checks the full record data, so it works regardless of which field holds the reference (`subject`, `parent`, `reply.root`, etc.).

## db.count

```lua
local n = db.count("xyz.statusphere.status")
local n = db.count("xyz.statusphere.status", "did:plc:abc")  -- filter by DID
```

## db.raw

Run a raw SQL query against the database. Supports `SELECT`, `INSERT`, `UPDATE`, `DELETE`, and `CREATE TABLE` statements.

```lua
-- Read query
local rows = db.raw(
  "SELECT uri, did, record FROM records WHERE collection = $1 AND did = $2 LIMIT $3",
  { "xyz.statusphere.status", "did:plc:abc", 10 }
)

for _, row in ipairs(rows) do
  -- row.uri, row.did, row.record (JSONB is returned as a Lua table)
end

-- Write query (returns affected rows, if any)
db.raw("CREATE TABLE IF NOT EXISTS my_table (id TEXT PRIMARY KEY, value TEXT NOT NULL)")
db.raw("INSERT INTO my_table (id, value) VALUES ($1, $2) ON CONFLICT (id) DO UPDATE SET value = $2",
  { "key1", "hello" })
```

Parameters are passed as an array and bound to `$1`, `$2`, etc. Supported parameter types: strings, integers, numbers, booleans, and nil.

### SQL dialect

Write SQL in **SQLite syntax** — HappyView translates it to Postgres at runtime if you're using Postgres. See [Database Setup](../../guides/database/database-setup.md) for details on what gets translated. If you need database-specific SQL that can't be translated, check `db.backend()` at runtime.

### Column type mapping

| SQLite type            | Postgres type          | Lua type |
| ---------------------- | ---------------------- | -------- |
| `TEXT`                 | `TEXT`, `VARCHAR`      | string   |
| `INTEGER`              | `INT4`, `INT8`         | integer  |
| `REAL`                 | `FLOAT4`, `FLOAT8`     | number   |
| `INTEGER` (0/1)        | `BOOL`                 | boolean  |
| `TEXT` (JSON)          | `JSON`, `JSONB`        | table    |
| `TEXT` (ISO 8601)      | `TIMESTAMPTZ`          | string (ISO 8601) |
| Other                  | Other                  | string (fallback)  |

## db.backend

```lua
local backend = db.backend()
-- "sqlite" or "postgres"
```

Returns `"sqlite"` or `"postgres"`. Useful when you need database-specific SQL that can't be automatically translated.

```lua
if db.backend() == "postgres" then
  db.raw("SELECT * FROM records WHERE record @> $1::jsonb", { json.encode({ status = "active" }) })
else
  -- SQLite fallback
  db.raw("SELECT * FROM records WHERE json_extract(record, '$.status') = $1", { "active" })
end
```
