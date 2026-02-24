# Admin API

The admin API lets you manage lexicons, monitor records, run backfill jobs, and control admin access. All endpoints live under `/admin` and require an [AIP](https://github.com/graze-social/aip)-issued Bearer token from a DID that exists in the `admins` table. You can also manage all of this through the [web dashboard](../getting-started/dashboard).

## Auth

Admin auth works the same as user auth: the Bearer token is validated against AIP's `/oauth/userinfo` endpoint to retrieve the caller's DID. That DID is then checked against the `admins` table.

**Auto-bootstrap**: If the `admins` table is empty, the first authenticated request automatically inserts the caller as the initial admin.

Non-admin DIDs receive a `403 Forbidden` response.

All error responses return JSON with an `error` field:

```json
{
  "error": "description of what went wrong"
}
```

| Status | Meaning |
|--------|---------|
| `400 Bad Request` | Invalid input (missing required fields, malformed lexicon JSON) |
| `401 Unauthorized` | Missing or invalid Bearer token. See [AIP documentation](https://github.com/graze-social/aip) for token issues |
| `403 Forbidden` | Authenticated DID is not in the admins table |
| `404 Not Found` | Lexicon, admin, or backfill job not found |

```sh
# All examples assume $TOKEN is an AIP-issued access token for an admin DID
AUTH="Authorization: Bearer $TOKEN"
```

## Lexicons

### Upload / upsert a lexicon

```
POST /admin/lexicons
```

```sh
curl -X POST http://localhost:3000/admin/lexicons \
  -H "$AUTH" \
  -H "Content-Type: application/json" \
  -d '{
    "lexicon_json": { "lexicon": 1, "id": "xyz.statusphere.status", "defs": { "main": { "type": "record", "key": "tid", "record": { "type": "object", "required": ["status", "createdAt"], "properties": { "status": { "type": "string", "maxGraphemes": 1 }, "createdAt": { "type": "string", "format": "datetime" } } } } } },
    "backfill": true,
    "target_collection": null
  }'
```

| Field               | Type    | Required | Description                                                         |
| ------------------- | ------- | -------- | ------------------------------------------------------------------- |
| `lexicon_json`      | object  | yes      | Raw lexicon JSON (must have `lexicon: 1` and `id`)                  |
| `backfill`          | boolean | no       | Whether uploading triggers historical backfill (default `true`)     |
| `target_collection` | string  | no       | For query/procedure lexicons, the record collection they operate on |

**Response**: `201 Created` (new) or `200 OK` (upsert)

```json
{
  "id": "xyz.statusphere.status",
  "revision": 1
}
```

### List lexicons

```
GET /admin/lexicons
```

```sh
curl http://localhost:3000/admin/lexicons -H "$AUTH"
```

**Response**: `200 OK`

```json
[
  {
    "id": "xyz.statusphere.status",
    "revision": 1,
    "lexicon_type": "record",
    "backfill": true,
    "created_at": "2025-01-01T00:00:00Z",
    "updated_at": "2025-01-01T00:00:00Z"
  }
]
```

### Get a lexicon

```
GET /admin/lexicons/{id}
```

```sh
curl http://localhost:3000/admin/lexicons/xyz.statusphere.status -H "$AUTH"
```

**Response**: `200 OK` with full lexicon details including raw JSON.

### Delete a lexicon

```
DELETE /admin/lexicons/{id}
```

```sh
curl -X DELETE http://localhost:3000/admin/lexicons/xyz.statusphere.status -H "$AUTH"
```

**Response**: `204 No Content`

## Network Lexicons

Network lexicons are fetched from the AT Protocol network via DNS TXT resolution and kept updated via Tap. See [Lexicons - Network lexicons](../guides/lexicons#network-lexicons) for background.

### Add a network lexicon

```
POST /admin/network-lexicons
```

```sh
curl -X POST http://localhost:3000/admin/network-lexicons \
  -H "$AUTH" \
  -H "Content-Type: application/json" \
  -d '{
    "nsid": "xyz.statusphere.status",
    "target_collection": null
  }'
```

| Field               | Type   | Required | Description                                                         |
| ------------------- | ------ | -------- | ------------------------------------------------------------------- |
| `nsid`              | string | yes      | The NSID of the lexicon to watch                                    |
| `target_collection` | string | no       | For query/procedure lexicons, the record collection they operate on |

HappyView resolves the NSID authority via DNS TXT, fetches the lexicon from the authority's PDS, parses it, and stores it.

**Response**: `201 Created`

```json
{
  "nsid": "xyz.statusphere.status",
  "authority_did": "did:plc:authority",
  "revision": 1
}
```

### List network lexicons

```
GET /admin/network-lexicons
```

```sh
curl http://localhost:3000/admin/network-lexicons -H "$AUTH"
```

**Response**: `200 OK`

```json
[
  {
    "nsid": "xyz.statusphere.status",
    "authority_did": "did:plc:authority",
    "target_collection": null,
    "last_fetched_at": "2025-01-01T00:00:00Z",
    "created_at": "2025-01-01T00:00:00Z"
  }
]
```

### Remove a network lexicon

```
DELETE /admin/network-lexicons/{nsid}
```

```sh
curl -X DELETE http://localhost:3000/admin/network-lexicons/xyz.statusphere.status \
  -H "$AUTH"
```

Removes the network lexicon tracking and also deletes the lexicon from the `lexicons` table and in-memory registry.

**Response**: `204 No Content`

## Stats

### Record counts

```
GET /admin/stats
```

```sh
curl http://localhost:3000/admin/stats -H "$AUTH"
```

**Response**: `200 OK`

```json
{
  "total_records": 12345,
  "collections": [{ "collection": "xyz.statusphere.status", "count": 500 }]
}
```

## Tap Stats

Aggregate stats from the [Tap](https://github.com/bluesky-social/indigo/tree/main/cmd/tap) instance. Useful for monitoring backfill progress. See [Backfill - Job lifecycle](../guides/backfill#job-lifecycle) for context.

### Get Tap stats

```
GET /admin/tap/stats
```

```sh
curl http://localhost:3000/admin/tap/stats -H "$AUTH"
```

**Response**: `200 OK`

```json
{
  "repo_count": 5234,
  "record_count": 1048576,
  "outbox_buffer": 42
}
```

| Field          | Type   | Description                                              |
| -------------- | ------ | -------------------------------------------------------- |
| `repo_count`   | number | Total repos Tap is tracking                              |
| `record_count` | number | Total records Tap has indexed                            |
| `outbox_buffer`| number | Pending events awaiting delivery (high = Tap is busy)    |

Returns `502 Bad Gateway` if Tap is unreachable.

## Backfill

### Create a backfill job

```
POST /admin/backfill
```

```sh
curl -X POST http://localhost:3000/admin/backfill \
  -H "$AUTH" \
  -H "Content-Type: application/json" \
  -d '{ "collection": "xyz.statusphere.status" }'
```

| Field        | Type   | Required | Description                                                |
| ------------ | ------ | -------- | ---------------------------------------------------------- |
| `collection` | string | no       | Limit to a single collection (backfills all if omitted)    |
| `did`        | string | no       | Limit to a single DID (discovers all via relay if omitted) |

**Response**: `201 Created`

```json
{
  "id": "550e8400-e29b-41d4-a716-446655440000",
  "status": "pending"
}
```

### List backfill jobs

```
GET /admin/backfill/status
```

```sh
curl http://localhost:3000/admin/backfill/status -H "$AUTH"
```

**Response**: `200 OK`

```json
[
  {
    "id": "550e8400-e29b-41d4-a716-446655440000",
    "collection": "xyz.statusphere.status",
    "did": null,
    "status": "completed",
    "total_repos": 42,
    "processed_repos": 42,
    "total_records": 1000,
    "error": null,
    "started_at": "2025-01-01T00:01:00Z",
    "completed_at": "2025-01-01T00:05:00Z",
    "created_at": "2025-01-01T00:00:00Z"
  }
]
```

## Admin management

### Add an admin

```
POST /admin/admins
```

```sh
curl -X POST http://localhost:3000/admin/admins \
  -H "$AUTH" \
  -H "Content-Type: application/json" \
  -d '{ "did": "did:plc:newadmin" }'
```

**Response**: `201 Created`

```json
{
  "id": "550e8400-e29b-41d4-a716-446655440000",
  "did": "did:plc:newadmin"
}
```

### List admins

```
GET /admin/admins
```

```sh
curl http://localhost:3000/admin/admins -H "$AUTH"
```

**Response**: `200 OK`

```json
[
  {
    "id": "550e8400-e29b-41d4-a716-446655440000",
    "did": "did:plc:admin",
    "created_at": "2025-01-01T00:00:00Z",
    "last_used_at": "2025-01-02T12:00:00Z"
  }
]
```

### Remove an admin

```
DELETE /admin/admins/{id}
```

```sh
curl -X DELETE http://localhost:3000/admin/admins/550e8400-e29b-41d4-a716-446655440000 \
  -H "$AUTH"
```

**Response**: `204 No Content`
