# Backfill

Create and monitor historical backfill jobs. See the [Backfill guide](../../guides/indexing/backfill.md) for background.

```sh
# All examples assume $TOKEN is an API key (hv_...)
AUTH="Authorization: Bearer $TOKEN"
```

## Create a backfill job

```
POST /admin/backfill
```

```sh
curl -X POST http://127.0.0.1:3000/admin/backfill \
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

## List backfill jobs

```
GET /admin/backfill/status
```

```sh
curl http://127.0.0.1:3000/admin/backfill/status -H "$AUTH"
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
