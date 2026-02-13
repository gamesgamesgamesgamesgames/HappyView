# Admin API

All admin endpoints live under `/admin` and require an AIP-issued Bearer token from a DID that exists in the `admins` table.

## Auth

Admin auth works the same as user auth — the Bearer token is validated against AIP's `/oauth/userinfo` endpoint to retrieve the caller's DID. That DID is then checked against the `admins` table.

**Auto-bootstrap**: If the `admins` table is empty, the first authenticated request automatically inserts the caller as the initial admin.

Non-admin DIDs receive a `403 Forbidden` response.

```sh
# All examples assume $TOKEN is an AIP-issued access token for an admin DID
AUTH="Authorization: Bearer $TOKEN"
```

---

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
    "lexicon_json": { "lexicon": 1, "id": "example.record", "defs": { "main": { "type": "record", "key": "tid", "record": { "type": "object", "properties": { "title": { "type": "string" } } } } } },
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
  "id": "example.record",
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
    "id": "example.record",
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
curl http://localhost:3000/admin/lexicons/example.record -H "$AUTH"
```

**Response**: `200 OK` with full lexicon details including raw JSON.

### Delete a lexicon

```
DELETE /admin/lexicons/{id}
```

```sh
curl -X DELETE http://localhost:3000/admin/lexicons/example.record -H "$AUTH"
```

**Response**: `204 No Content`

---

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
  "collections": [{ "collection": "example.record", "count": 500 }]
}
```

---

## Backfill

### Create a backfill job

```
POST /admin/backfill
```

```sh
curl -X POST http://localhost:3000/admin/backfill \
  -H "$AUTH" \
  -H "Content-Type: application/json" \
  -d '{ "collection": "example.record" }'
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
    "collection": "example.record",
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

---

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
