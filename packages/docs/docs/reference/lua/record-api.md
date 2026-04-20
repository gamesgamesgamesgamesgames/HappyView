# Record API

The `Record` API is only available in **procedure** scripts. It handles creating, updating, loading, and deleting atproto records. Writes are proxied to the caller's PDS and indexed locally.

## Constructor

```lua
local r = Record("xyz.statusphere.status", { status = "\ud83d\ude0a", createdAt = now() })
```

Creates a new record instance for the given collection. The optional second argument sets initial field values. The record's `_key_type` is automatically set from the lexicon's `key` definition. Default values from the schema are populated for any missing fields.

## Static methods

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

## Instance methods

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

## Instance fields

These fields are set automatically and are read-only (writes raise an error):

| Field         | Type    | Description                                                 |
| ------------- | ------- | ----------------------------------------------------------- |
| `_uri`        | string? | AT URI — set after `save()`, cleared after `delete()`       |
| `_cid`        | string? | Content hash — set after `save()`, cleared after `delete()` |
| `_key_type`   | string? | Record key type from the lexicon definition                 |
| `_rkey`       | string? | Record key — set via `set_rkey()` or `generate_rkey()`      |
| `_collection` | string  | Collection NSID (always set)                                |
| `_schema`     | table?  | Schema definition from the lexicon (used for validation)    |

## Schema validation

When a record has a schema (loaded from the lexicon):

- **On save:** required fields are checked, and missing required fields raise an error
- **On construction:** default values from schema properties are auto-populated
- **On save:** only fields defined in the schema's `properties` are sent to the PDS

## Save behavior

`r:save()` auto-detects create vs update:

- If `_uri` is nil → calls `createRecord` on the PDS
- If `_uri` is set → calls `putRecord` on the PDS

After a successful save, `_uri` and `_cid` are updated on the record instance.
