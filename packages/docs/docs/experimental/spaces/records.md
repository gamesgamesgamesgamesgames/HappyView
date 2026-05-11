# Records

:::caution Experimental
This API is experimental and will change. See the [Permissioned Spaces overview](../spaces.md) for context.
:::

Space records are stored separately from public AT Protocol records. They follow the same URI pattern but use the `ats://` scheme and include the space identity:

```
ats:// did:plc:abcdefghijklmnop1234567890 / com.example.forum / main        / did:plc:author / com.example.forum.post / abcdefghijklmnop1234567890
       └── space DID ───────────────────┘   └── space type ─┘   └── skey ─┘   └── author ──┘   └── collection ──────┘   └── rkey ────────────────┘
```

## Creating a record

Requires `write` membership in the space. The rkey is auto-generated using a TID.

```sh
curl -X POST 'https://happyview.example.com/xrpc/dev.happyview.space.createRecord' \
  -H 'X-Client-Key: hvc_...' \
  -H 'Authorization: DPoP <token>' \
  -H 'DPoP: <proof>' \
  -H 'Content-Type: application/json' \
  -d '{
    "space": "ats://did:plc:abc123/com.example.forum/main",
    "collection": "com.example.forum.post",
    "record": {
      "$type": "com.example.forum.post",
      "text": "Hello from the forum!",
      "createdAt": "2026-05-09T12:00:00Z"
    }
  }'
```

**Input:**

| Field        | Type          | Required | Description             |
| ------------ | ------------- | -------- | ----------------------- |
| `space`      | string        | Yes      | The space to write into |
| `collection` | string (NSID) | Yes      | The record collection   |
| `record`     | object        | Yes      | The record data         |

**Response (201):**

```json
{
  "uri": "ats://did:plc:abc123/com.example.forum/main/did:plc:author/com.example.forum.post/3l2tkbx7225co",
  "cid": "bafyrei..."
}
```

`createRecord` always inserts a new record. If a record with the generated URI already exists, it returns `409 Conflict`.

## Writing a record (put)

Requires `write` membership in the space.

```sh
curl -X POST 'https://happyview.example.com/xrpc/dev.happyview.space.putRecord' \
  -H 'X-Client-Key: hvc_...' \
  -H 'Authorization: DPoP <token>' \
  -H 'DPoP: <proof>' \
  -H 'Content-Type: application/json' \
  -d '{
    "space": "ats://did:plc:abc123/com.example.forum/main",
    "collection": "com.example.forum.post",
    "rkey": "3k2abc",
    "record": {
      "$type": "com.example.forum.post",
      "text": "Hello from the forum!",
      "createdAt": "2026-05-09T12:00:00Z"
    }
  }'
```

**Input:**

| Field        | Type          | Required | Description                                                      |
| ------------ | ------------- | -------- | ---------------------------------------------------------------- |
| `space`      | string        | Yes      | The space to write into                                          |
| `collection` | string (NSID) | Yes      | The record collection                                            |
| `rkey`       | string        | Yes      | The record key                                                   |
| `record`     | object        | Yes      | The record data                                                  |
| `swapRecord` | string        | No       | Expected CID of the existing record (for optimistic concurrency) |

**Response (201):**

```json
{
  "uri": "ats://did:plc:abc123/com.example.forum/main/did:plc:author/com.example.forum.post/3k2abc",
  "cid": "bafyrei..."
}
```

The author DID is taken from the authenticated user. You can only write records as yourself, so the URI's author component will always be your DID.

`putRecord` performs an upsert: if a record with the same collection + rkey already exists for this author in this space, it's overwritten. Use `swapRecord` to prevent unintended overwrites (see [Optimistic concurrency](#optimistic-concurrency) below).

## Getting a record

Requires `read` membership (or a valid [space credential](credentials.md)).

```sh
curl 'https://happyview.example.com/xrpc/dev.happyview.space.getRecord?space=ats://did:plc:abc123/com.example.forum/main&collection=com.example.forum.post&rkey=3k2abc' \
  -H 'X-Client-Key: hvc_...' \
  -H 'Authorization: DPoP <token>' \
  -H 'DPoP: <proof>'
```

**Response:**

```json
{
  "uri": "ats://did:plc:abc123/com.example.forum/main/did:plc:author/com.example.forum.post/3k2abc",
  "cid": "bafyrei...",
  "value": {
    "$type": "com.example.forum.post",
    "text": "Hello from the forum!",
    "createdAt": "2026-05-09T12:00:00Z"
  }
}
```

## Listing records

```sh
curl 'https://happyview.example.com/xrpc/dev.happyview.space.listRecords?space=ats://did:plc:abc123/com.example.forum/main&collection=com.example.forum.post&limit=20' \
  -H 'X-Client-Key: hvc_...' \
  -H 'Authorization: DPoP <token>' \
  -H 'DPoP: <proof>'
```

**Parameters:**

| Field        | Type    | Required | Default | Description                       |
| ------------ | ------- | -------- | ------- | --------------------------------- |
| `space`      | string  | Yes      |         | The space to list from            |
| `repo`       | string  | No       |         | Filter by author DID              |
| `collection` | string  | No       |         | Filter by collection NSID         |
| `limit`      | integer | No       | 50      | Max records to return (1-100)     |
| `cursor`     | string  | No       |         | Pagination cursor                 |
| `reverse`    | boolean | No       | `false` | Reverse sort order (oldest first) |

**Response:**

```json
{
  "records": [
    {
      "collection": "com.example.forum.post",
      "rkey": "3k2abc",
      "cid": "bafyrei..."
    }
  ],
  "cursor": "2026-05-09T12:00:00Z"
}
```

## Deleting a record

You can only delete your own records. Requires `write` membership.

```sh
curl -X POST 'https://happyview.example.com/xrpc/dev.happyview.space.deleteRecord' \
  -H 'X-Client-Key: hvc_...' \
  -H 'Authorization: DPoP <token>' \
  -H 'DPoP: <proof>' \
  -H 'Content-Type: application/json' \
  -d '{
    "space": "ats://did:plc:abc123/com.example.forum/main",
    "collection": "com.example.forum.post",
    "rkey": "3k2abc"
  }'
```

**Input:**

| Field        | Type          | Required | Description                                                      |
| ------------ | ------------- | -------- | ---------------------------------------------------------------- |
| `space`      | string        | Yes      | The space containing the record                                  |
| `collection` | string (NSID) | Yes      | The record collection                                            |
| `rkey`       | string        | Yes      | The record key                                                   |
| `swapRecord` | string        | No       | Expected CID of the existing record (for optimistic concurrency) |

Attempting to delete another user's record returns `403 Forbidden`.

## Batch writes (applyWrites)

`applyWrites` performs multiple create, update, and delete operations in a single request. Requires `write` membership.

```sh
curl -X POST 'https://happyview.example.com/xrpc/dev.happyview.space.applyWrites' \
  -H 'X-Client-Key: hvc_...' \
  -H 'Authorization: DPoP <token>' \
  -H 'DPoP: <proof>' \
  -H 'Content-Type: application/json' \
  -d '{
    "space": "ats://did:plc:abc123/com.example.forum/main",
    "writes": [
      {
        "action": "create",
        "collection": "com.example.forum.post",
        "value": { "$type": "com.example.forum.post", "text": "First post" }
      },
      {
        "action": "update",
        "collection": "com.example.forum.post",
        "rkey": "3k2abc",
        "value": { "$type": "com.example.forum.post", "text": "Edited post" },
        "swapRecord": "bafyrei..."
      },
      {
        "action": "delete",
        "collection": "com.example.forum.post",
        "rkey": "old-post"
      }
    ]
  }'
```

**Input:**

| Field        | Type   | Required | Description                                          |
| ------------ | ------ | -------- | ---------------------------------------------------- |
| `space`      | string | Yes      | The space to write into                              |
| `swapCommit` | string | No       | Expected space revision (for optimistic concurrency) |
| `writes`     | array  | Yes      | List of write operations                             |

Each write operation has an `action` field:

| Action   | Fields                                       | Description                                          |
| -------- | -------------------------------------------- | ---------------------------------------------------- |
| `create` | `collection`, `value`, `rkey?`               | Insert a new record. Auto-generates rkey if omitted. |
| `update` | `collection`, `rkey`, `value`, `swapRecord?` | Upsert a record.                                     |
| `delete` | `collection`, `rkey`, `swapRecord?`          | Delete a record.                                     |

**Response:**

```json
{
  "results": [
    { "uri": "ats://...", "cid": "bafyrei..." },
    { "uri": "ats://...", "cid": "bafyrei..." },
    {}
  ]
}
```

Each entry in `results` corresponds to the write at the same index. Create and update operations return `uri` and `cid`; delete operations return an empty object.

## Optimistic concurrency

`swapRecord` and `swapCommit` provide optimistic concurrency control to prevent lost updates when multiple clients write to the same space.

### swapRecord

Pass the `swapRecord` field on `putRecord`, `deleteRecord`, or individual operations within `applyWrites`. The value is the CID of the record you expect to be replacing. If the record's current CID doesn't match, the operation fails with `409 Conflict`.

```json
{
  "space": "ats://did:plc:abc123/com.example.forum/main",
  "collection": "com.example.forum.post",
  "rkey": "3k2abc",
  "record": { "text": "updated safely" },
  "swapRecord": "bafyrei_old_cid"
}
```

### swapCommit

Pass the `swapCommit` field on `applyWrites` to assert the space's current revision. If another client has written to the space since you last read its state, the operation fails with `409 Conflict` before any writes are applied.

The space's current revision is available as `revision` in the space object returned by `dev.happyview.space.getSpace`.

```json
{
  "space": "ats://did:plc:abc123/com.example.forum/main",
  "swapCommit": "3l2tkbx7225co",
  "writes": [...]
}
```

## Cross-service access

Records can also be read using a [space credential](credentials.md) instead of direct membership. Pass the credential as a Bearer token:

```sh
curl 'https://happyview.example.com/xrpc/dev.happyview.space.getRecord?...' \
  -H 'Authorization: Bearer eyJhbGciOiJFUzI1NiIsInR5cCI6InNwYWNlX2NyZWRlbnRpYWwifQ...'
```

A feed generator or other service that isn't a direct member can use a credential issued by the space owner to read data without joining the space. No DPoP auth is needed — the credential itself authenticates the request.
