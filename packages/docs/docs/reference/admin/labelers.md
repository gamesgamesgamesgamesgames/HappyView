# Admin API: Labelers

Manage external labeler subscriptions. See the [Labelers guide](../../guides/features/labelers.md) for background.

```sh
# All examples assume $TOKEN is an API key (hv_...)
AUTH="Authorization: Bearer $TOKEN"
```

## Add a labeler

```
POST /admin/labelers
```

Requires `labelers:create` permission.

```sh
curl -X POST http://localhost:3000/admin/labelers \
  -H "$AUTH" \
  -H "Content-Type: application/json" \
  -d '{ "did": "did:plc:ar7c4by46qjdydhdevvrndac" }'
```

| Field | Type   | Required | Description                   |
| ----- | ------ | -------- | ----------------------------- |
| `did` | string | yes      | The labeler's atproto DID |

**Response**: `201 Created` (empty body)

## List labelers

```
GET /admin/labelers
```

Requires `labelers:read` permission.

```sh
curl http://localhost:3000/admin/labelers -H "$AUTH"
```

**Response**: `200 OK`

```json
[
  {
    "did": "did:plc:ar7c4by46qjdydhdevvrndac",
    "status": "active",
    "cursor": 1234,
    "created_at": "2026-03-15T00:00:00Z",
    "updated_at": "2026-03-15T00:00:00Z"
  }
]
```

| Field        | Type         | Description                                        |
| ------------ | ------------ | -------------------------------------------------- |
| `did`        | string       | The labeler's DID                                  |
| `status`     | string       | `active` or `paused`                               |
| `cursor`     | number\|null | Last processed event cursor (null if never synced) |
| `created_at` | string       | ISO 8601 creation timestamp                        |
| `updated_at` | string       | ISO 8601 last-updated timestamp                    |

## Update a labeler

```
PATCH /admin/labelers/{did}
```

Requires `labelers:create` permission.

```sh
curl -X PATCH http://localhost:3000/admin/labelers/did:plc:ar7c4by46qjdydhdevvrndac \
  -H "$AUTH" \
  -H "Content-Type: application/json" \
  -d '{ "status": "paused" }'
```

| Field    | Type   | Required | Description                      |
| -------- | ------ | -------- | -------------------------------- |
| `status` | string | yes      | New status: `active` or `paused` |

**Response**: `200 OK`

## Delete a labeler

```
DELETE /admin/labelers/{did}
```

Requires `labelers:delete` permission. Removes the subscription and all labels emitted by this labeler.

```sh
curl -X DELETE http://localhost:3000/admin/labelers/did:plc:ar7c4by46qjdydhdevvrndac \
  -H "$AUTH"
```

**Response**: `204 No Content`
