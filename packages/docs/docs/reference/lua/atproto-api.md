# atproto API

The `atproto` table provides atproto utility functions. Available in queries, procedures, and [index hooks](../../guides/indexing/index-hooks.md).

## atproto.resolve_service_endpoint

```lua
local endpoint = atproto.resolve_service_endpoint(did)
```

Resolves a DID to its atproto service endpoint URL by fetching the DID document. Supports both `did:plc:*` (via the PLC directory) and `did:web:*` (via `.well-known/did.json`).

| Parameter | Type   | Description              |
| --------- | ------ | ------------------------ |
| `did`     | string | The DID to resolve       |

**Returns:** The service endpoint URL as a string, or `nil` if resolution fails (DID not found, no PDS service in document, network error).

### Examples

```lua
-- Resolve a did:plc DID
local endpoint = atproto.resolve_service_endpoint("did:plc:abc123")
-- endpoint = "https://pds.example.com"

-- Resolve a did:web DID
local endpoint = atproto.resolve_service_endpoint("did:web:example.com")
-- endpoint = "https://example.com"

-- Handle resolution failure
local endpoint = atproto.resolve_service_endpoint("did:plc:unknown")
if not endpoint then
  return { error = "Could not resolve DID" }
end

-- Use with HTTP API to call a remote XRPC endpoint
local endpoint = atproto.resolve_service_endpoint(did)
if endpoint then
  local resp = http.get(endpoint .. "/xrpc/com.example.method")
  local data = json.decode(resp.body)
end
```

## atproto.get_labels

```lua
local labels = atproto.get_labels(uri)
```

Returns an array of labels for a single AT URI. Merges external labels (from subscribed labelers) with self-labels (from the record's `labels.values[]` field).

| Parameter | Type   | Description                    |
| --------- | ------ | ------------------------------ |
| `uri`     | string | AT URI of the record to query  |

Each label in the array is a table with:

| Field | Type   | Description                              |
| ----- | ------ | ---------------------------------------- |
| `src` | string | DID of the labeler (or record author)    |
| `uri` | string | AT URI this label applies to             |
| `val` | string | Label value (e.g. "nsfw", "!hide")       |
| `cts` | string | Timestamp when the label was created     |

Expired labels are automatically filtered out. Returns an empty array if no labels exist.

## atproto.get_labels_batch

```lua
local labels_by_uri = atproto.get_labels_batch(uris)
```

Batch version of `get_labels`. Takes an array of AT URIs and returns a table keyed by URI, where each value is an array of labels.

| Parameter | Type  | Description              |
| --------- | ----- | ------------------------ |
| `uris`    | table | Array of AT URI strings  |

**Returns:** A table keyed by URI. Each value is an array of label tables (same shape as `get_labels`). URIs with no labels have an empty array.

### Label examples

```lua
-- Get labels for a single game
local labels = atproto.get_labels("at://did:plc:abc/games.gamesgamesgamesgames.game/rkey1")
for _, label in ipairs(labels) do
  if label.val == "!hide" then
    -- skip this game in feed results
  end
end

-- Batch fetch labels for multiple games (efficient for feed hydration)
local uris = {}
for _, item in ipairs(skeleton) do
  uris[#uris + 1] = item.game
end

local labels_by_uri = atproto.get_labels_batch(uris)
for _, uri in ipairs(uris) do
  local labels = labels_by_uri[uri]
  for _, label in ipairs(labels) do
    if label.val == "!hide" then
      -- filter out this game
    end
  end
end
```
