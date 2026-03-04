# Index Hooks

Index hooks are Lua scripts that run automatically whenever a record in a collection is created, updated, or deleted on the network. They let you react to record changes in real time — push data to search engines, sync with external APIs, send notifications, or build materialized views.

Unlike [query and procedure scripts](scripting.md) that run in response to XRPC requests, index hooks are triggered by the firehose. They run asynchronously and never block record indexing.

## Attaching a hook

Each record-type lexicon can have one index hook. You can add it through the [dashboard](../getting-started/dashboard.md) (click "Add Index Hook" on any record lexicon's detail page) or via the [admin API](../reference/admin-api.md#upload--upsert-a-lexicon) by including the `index_hook` field when uploading a lexicon.

## Script structure

Like query and procedure scripts, index hooks must define a `handle()` function:

```lua
function handle()
  if action == "delete" then
    log("deleted " .. uri)
  else
    log(action .. " " .. uri)
  end
end
```

The function is called once per record event. There is no return value — index hooks are fire-and-forget from the caller's perspective.

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

Index hooks do **not** have access to `caller_did`, `input`, `params`, `method`, or the `Record` API. They run from the firehose, not from a user request.

## Available APIs

Index hooks have access to:

- **[Database API](scripting.md#database-api)** — `db.query`, `db.get`, `db.search`, `db.backlinks`, `db.count`, `db.raw`
- **[HTTP API](scripting.md#http-api)** — `http.get`, `http.post`, `http.put`, `http.patch`, `http.delete`, `http.head`
- **[JSON API](scripting.md#json-api)** — `json.encode`, `json.decode`
- **[Utility globals](scripting.md#utility-globals)** — `log()`, `now()`, `TID()`, `toarray()`

## Error handling and retries

Index hooks are designed to be resilient:

1. If a hook fails, it retries up to **3 times** with exponential backoff (1s, 2s, 4s delays).
2. If all retries are exhausted, the failed event is inserted into the `dead_letter_hooks` table for later inspection.
3. Hook failures never block record indexing — the record is always indexed regardless of whether the hook succeeds.

Failed hooks are logged as errors. Check the [event logs](event-logs.md) or query the `dead_letter_hooks` table directly to find and replay failures.

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
end
```

See the full [Algolia sync reference](../reference/scripts/algolia-sync.md) for more detail.

## Next steps

- [Lua Scripting](scripting.md): Full reference for the sandbox, APIs, and debugging
- [Lexicons](lexicons.md): Understand how record, query, and procedure lexicons work together
- [Admin API](../reference/admin-api.md#upload--upsert-a-lexicon): Upload lexicons with index hooks via the API
