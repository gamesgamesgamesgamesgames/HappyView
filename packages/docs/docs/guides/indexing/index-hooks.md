# Index Hooks

Index hooks are Lua scripts that run whenever a record in a collection is created, updated, or deleted. They run **before** the record is indexed, giving you the ability to filter out unwanted records, transform record data before storage, or trigger side effects like syncing with external services.

Index hooks fire on **all** record events for the collection — including records created by HappyView procedure endpoints, not just events from the network. Unlike [query and procedure scripts](../scripting.md) that run in response to XRPC requests, index hooks are triggered by incoming Jetstream events (which include events caused by HappyView's own PDS writes).

## Attaching a hook

Each record-type lexicon can have one index hook. You can add it through the [dashboard](../../getting-started/dashboard.md) (click "Add Index Hook" on any record lexicon's detail page) or via the [admin API](../../reference/admin/lexicons.md#upload--upsert-a-lexicon) by including the `index_hook` field when uploading a lexicon.

## Script structure

Like query and procedure scripts, index hooks must define a `handle()` function:

```lua
function handle()
  if action == "delete" then
    log("deleted " .. uri)
  else
    log(action .. " " .. uri)
  end
  return true
end
```

The function is called once per record event. The return value controls what happens next:

| Return value | Effect                                                      |
| ------------ | ----------------------------------------------------------- |
| `nil`        | The record is **not** indexed (skipped entirely)            |
| A table      | That table is stored as the record instead                  |
| `true`       | The original record is stored as-is                         |
| *(no hook)*  | The original record is stored as-is                         |

On **delete** events, returning `nil` skips the delete (the record stays in the database).

**Important:** If your hook has side effects (e.g. syncing to a search index) but you want normal indexing to proceed, return `record` or `true` — not nothing. A missing return statement returns `nil`, which **skips indexing**.

If the hook errors after all retries, the system **fails open** — the original record is stored and the failed event is dead-lettered for later inspection.

## Context globals

These globals are set before `handle()` is called:

| Global       | Type   | Description                                        |
| ------------ | ------ | -------------------------------------------------- |
| `action`     | string | `"create"`, `"update"`, or `"delete"`              |
| `uri`        | string | The full AT URI (e.g. `at://did:plc:abc/col/rkey`) |
| `did`        | string | The repo DID                                       |
| `collection` | string | The collection NSID                                |
| `rkey`       | string | The record key                                     |
| `record`     | table? | The full record as a Lua table (nil on delete)     |

Index hooks do **not** have access to `caller_did`, `input`, `params`, `method`, or the `Record` API. They run from the Jetstream event stream, not from a user request.

## Available APIs

Index hooks have access to:

- **[Database API](../../reference/lua/database-api.md)** — `db.query`, `db.get`, `db.search`, `db.backlinks`, `db.count`, `db.raw`
- **[HTTP API](../../reference/lua/http-api.md)** — `http.get`, `http.post`, `http.put`, `http.patch`, `http.delete`, `http.head`
- **[JSON API](../../reference/lua/json-api.md)** — `json.encode`, `json.decode`
- **[Utility globals](../scripting.md#utility-globals)** — `log()`, `now()`, `TID()`, `toarray()`

## Error handling and retries

Index hooks are designed to be resilient:

1. If a hook fails, it retries up to **3 times** with exponential backoff (1s, 2s, 4s delays).
2. If all retries are exhausted, the failed event is inserted into the `dead_letter_hooks` table for later inspection.
3. On failure the system **fails open** — the original record is stored as-is so indexing is not permanently blocked.

Failed hooks are logged as errors. Check the [event logs](../admin/event-logs.md) or query the `dead_letter_hooks` table directly to find and replay failures.

### Performance considerations

Because hooks run synchronously before indexing, they block the Jetstream consumer while executing. With retry logic (1s + 2s + 4s backoff), a persistently failing hook could block for ~7 seconds per record. Keep hook scripts fast and ensure external services they depend on are reliable.

### Dead letter table

The `dead_letter_hooks` table stores events that failed all retry attempts:

| Column       | Type        | Description                             |
| ------------ | ----------- | --------------------------------------- |
| `id`         | UUID        | Primary key                             |
| `lexicon_id` | text        | The lexicon NSID                        |
| `uri`        | text        | The AT URI of the record                |
| `did`        | text        | The repo DID                            |
| `collection` | text        | The collection NSID                     |
| `rkey`       | text        | The record key                          |
| `action`     | text        | `create`, `update`, or `delete`         |
| `record`     | jsonb       | The record data (null on delete)        |
| `error`      | text        | The error message from the last attempt |
| `attempts`   | int         | Total number of attempts made           |
| `created_at` | timestamptz | When the failure was recorded           |

## Examples

### Filter out records missing a required field

Skip indexing any record that doesn't have a `title` field:

```lua
function handle()
  if action == "delete" then
    return record  -- allow deletes to proceed
  end

  if record.title == nil or record.title == "" then
    return nil  -- skip: no title
  end

  return record
end
```

### Transform a record before storage

Enrich a record with a computed field before it is stored:

```lua
function handle()
  if action == "delete" then
    return record
  end

  record.slug = string.lower(string.gsub(record.title or "", "%s+", "-"))
  return record
end
```

### Post to a webhook

```lua
function handle()
  http.post("https://hooks.example.com/records", {
    headers = { ["Content-Type"] = "application/json" },
    body = json.encode({
      action = action,
      uri = uri,
      did = did,
      record = record
    })
  })
  return record
end
```

### Sync to Algolia

Push records to an Algolia search index on create/update, and remove them on delete:

```lua
function handle()
  local headers = {
    ["X-Algolia-API-Key"] = "your-api-key",
    ["X-Algolia-Application-Id"] = "your-app-id",
    ["Content-Type"] = "application/json"
  }

  if action == "delete" then
    http.delete("https://YOUR-APP.algolia.net/1/indexes/records/" .. uri, {
      headers = headers
    })
  else
    http.put("https://YOUR-APP.algolia.net/1/indexes/records/" .. uri, {
      headers = headers,
      body = json.encode({
        objectID = uri,
        collection = collection,
        did = did,
        record = record
      })
    })
  end

  return record
end
```

See the full [Algolia sync reference](../scripting/algolia-sync.md) for more detail.

### Sync to Meilisearch

Push records to a self-hosted Meilisearch index on create/update, and remove them on delete:

```lua
function handle()
  local headers = {
    ["Authorization"] = "Bearer " .. env.MEILISEARCH_API_KEY,
    ["Content-Type"] = "application/json"
  }

  if action == "delete" then
    http.delete(env.MEILISEARCH_URL .. "/indexes/records/documents/" .. uri, {
      headers = headers
    })
  else
    http.post(env.MEILISEARCH_URL .. "/indexes/records/documents", {
      headers = headers,
      body = json.encode(toarray({
        {
          id = uri,
          collection = collection,
          did = did,
          record = record
        }
      }))
    })
  end

  return record
end
```

See the full [Meilisearch sync reference](../scripting/meilisearch-sync.md) for more detail.

## Next steps

- [Lua Scripting](../scripting.md): Full reference for the sandbox, APIs, and debugging
- [Lexicons](lexicons.md): Understand how record, query, and procedure lexicons work together
- [Admin API — Lexicons](../../reference/admin/lexicons.md#upload--upsert-a-lexicon): Upload lexicons with index hooks via the API
