# Admin API

The admin API lets you manage lexicons, monitor records, run backfill jobs, and control user access. All endpoints live under `/admin` and require an [AIP](https://github.com/graze-social/aip)-issued Bearer token from a DID that exists in the `users` table, with the appropriate [permissions](../guides/permissions.md) for the endpoint being called. You can also manage all of this through the [web dashboard](../getting-started/dashboard.md).

## Auth

The admin API supports two authentication methods:

1. **OAuth (AIP)** — the Bearer token is validated against AIP's `/oauth/userinfo` endpoint to retrieve the caller's DID.
2. **API keys** — read/write tokens starting with `hv_`. See the [API Keys guide](../guides/api-keys.md) for details.

In both cases the resolved DID is checked against the `users` table, and the user's permissions are loaded to authorize the request.

**Auto-bootstrap**: If the `users` table is empty, the first authenticated request automatically creates the caller as the **super user** with all permissions granted.

Non-user DIDs receive a `403 Forbidden` response. Users without the required permission for a specific endpoint also receive `403 Forbidden`.

All error responses return JSON with an `error` field:

```json
{
  "error": "description of what went wrong"
}
```

| Status             | Meaning                                                                                                        |
| ------------------ | -------------------------------------------------------------------------------------------------------------- |
| `400 Bad Request`  | Invalid input (missing required fields, malformed lexicon JSON)                                                |
| `401 Unauthorized` | Missing or invalid Bearer token. See [AIP documentation](https://github.com/graze-social/aip) for token issues |
| `403 Forbidden`    | Authenticated DID is not in the users table, or user lacks the required permission                             |
| `404 Not Found`    | Lexicon, user, or backfill job not found                                                                       |

```sh
# All examples assume $TOKEN is an AIP-issued access token or API key
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

| Field               | Type    | Required | Description                                                           |
| ------------------- | ------- | -------- | --------------------------------------------------------------------- |
| `lexicon_json`      | object  | yes      | Raw lexicon JSON (must have `lexicon: 1` and `id`)                    |
| `backfill`          | boolean | no       | Whether uploading triggers historical backfill (default `true`)       |
| `target_collection` | string  | no       | For query/procedure lexicons, the record collection they operate on   |
| `script`            | string  | no       | Lua script for query/procedure endpoints                              |
| `index_hook`        | string  | no       | [Index hook](../guides/index-hooks.md) Lua script for record lexicons |

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

Network lexicons are fetched from the AT Protocol network via DNS TXT resolution and kept updated via Tap. See [Lexicons - Network lexicons](../guides/lexicons.md#network-lexicons) for background.

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

Aggregate stats from the [Tap](https://github.com/bluesky-social/indigo/tree/main/cmd/tap) instance. Useful for monitoring backfill progress. See [Backfill - Job lifecycle](../guides/backfill.md#job-lifecycle) for context.

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

| Field           | Type   | Description                                           |
| --------------- | ------ | ----------------------------------------------------- |
| `repo_count`    | number | Total repos Tap is tracking                           |
| `record_count`  | number | Total records Tap has indexed                         |
| `outbox_buffer` | number | Pending events awaiting delivery (high = Tap is busy) |

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

## Event Logs

HappyView records an audit trail of system events: lexicon changes, record operations, Lua script executions and errors, user actions, backfill jobs, and Tap connectivity. See the [Event Logs guide](../guides/event-logs.md) for details on event types and retention.

### List event logs

```
GET /admin/events
```

```sh
curl "http://localhost:3000/admin/events?severity=error&limit=10" -H "$AUTH"
```

| Param        | Type   | Required | Description                                                           |
| ------------ | ------ | -------- | --------------------------------------------------------------------- |
| `event_type` | string | no       | Filter by exact event type (e.g. `script.error`)                      |
| `category`   | string | no       | Filter by category prefix (e.g. `lexicon` matches all lexicon events) |
| `severity`   | string | no       | Filter by severity: `info`, `warn`, or `error`                        |
| `subject`    | string | no       | Filter by subject (lexicon ID, record URI, admin DID, etc.)           |
| `cursor`     | string | no       | Pagination cursor (ISO 8601 timestamp from previous response)         |
| `limit`      | number | no       | Results per page (default `50`, max `100`)                            |

**Response**: `200 OK`

```json
{
  "events": [
    {
      "id": "550e8400-e29b-41d4-a716-446655440000",
      "event_type": "script.error",
      "severity": "error",
      "actor_did": "did:plc:abc123",
      "subject": "com.example.feed.like",
      "detail": {
        "error": "attempt to index nil value",
        "script_source": "function handle() ... end",
        "input": { "status": "hello" },
        "caller_did": "did:plc:abc123",
        "method": "com.example.feed.like"
      },
      "created_at": "2026-03-01T12:00:00Z"
    }
  ],
  "cursor": "2026-03-01T11:59:00Z"
}
```

Events are returned in reverse chronological order (newest first). Pass the `cursor` value from the response to fetch the next page.

## API Keys

Manage API keys for programmatic access. See the [API Keys guide](../guides/api-keys.md) for usage details.

### Create an API key

```
POST /admin/api-keys
```

Requires `api-keys:create` permission.

```sh
curl -X POST http://localhost:3000/admin/api-keys \
  -H "$AUTH" \
  -H "Content-Type: application/json" \
  -d '{
    "name": "CI Deploy",
    "permissions": ["lexicons:read", "lexicons:create", "backfill:create"]
  }'
```

| Field         | Type     | Required | Description                                                                                  |
| ------------- | -------- | -------- | -------------------------------------------------------------------------------------------- |
| `name`        | string   | yes      | A label to identify this key's usage                                                         |
| `permissions` | string[] | yes      | Permissions to grant the key (must be a subset of the creating user's own permissions)        |

**Response**: `201 Created`

```json
{
  "id": "550e8400-e29b-41d4-a716-446655440000",
  "name": "CI Deploy",
  "key": "hv_a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4",
  "key_prefix": "hv_a1b2c3d4",
  "permissions": ["lexicons:read", "lexicons:create", "backfill:create"]
}
```

The `key` field contains the full API key. It is only returned in this response — store it securely. The key's effective permissions are the **intersection** of the permissions specified here and the creating user's permissions at the time of each request.

### List API keys

```
GET /admin/api-keys
```

Requires `api-keys:read` permission.

```sh
curl http://localhost:3000/admin/api-keys -H "$AUTH"
```

**Response**: `200 OK`

```json
[
  {
    "id": "550e8400-e29b-41d4-a716-446655440000",
    "name": "CI Deploy",
    "key_prefix": "hv_a1b2c3d4",
    "permissions": ["lexicons:read", "lexicons:create", "backfill:create"],
    "created_at": "2026-03-01T00:00:00Z",
    "last_used_at": "2026-03-06T12:00:00Z",
    "revoked_at": null
  }
]
```

Only returns keys belonging to the authenticated user. The full key is never included — only the prefix.

### Revoke an API key

```
DELETE /admin/api-keys/{id}
```

Requires `api-keys:delete` permission.

```sh
curl -X DELETE http://localhost:3000/admin/api-keys/550e8400-e29b-41d4-a716-446655440000 \
  -H "$AUTH"
```

Sets `revoked_at` on the key. The key remains in the database for audit purposes but can no longer authenticate.

**Response**: `204 No Content`

## User Management

### Create a user

```
POST /admin/users
```

Requires `users:create` permission. You cannot grant permissions you don't have yourself (escalation guard).

```sh
curl -X POST http://localhost:3000/admin/users \
  -H "$AUTH" \
  -H "Content-Type: application/json" \
  -d '{
    "did": "did:plc:newuser",
    "template": "operator"
  }'
```

| Field         | Type     | Required | Description                                                                                       |
| ------------- | -------- | -------- | ------------------------------------------------------------------------------------------------- |
| `did`         | string   | yes      | The AT Protocol DID of the user to add                                                            |
| `template`    | string   | no       | Permission template: `viewer`, `operator`, `manager`, or `full_access`                            |
| `permissions` | string[] | no       | Explicit list of permissions to grant (used instead of or in addition to `template`)               |

If neither `template` nor `permissions` is provided, the user is created with no permissions.

**Response**: `201 Created`

```json
{
  "id": "550e8400-e29b-41d4-a716-446655440000",
  "did": "did:plc:newuser",
  "is_super": false,
  "permissions": ["lexicons:read", "records:read", "script-variables:read", "users:read", "api-keys:read", "api-keys:create", "api-keys:delete", "backfill:read", "backfill:create", "stats:read", "events:read"]
}
```

### List users

```
GET /admin/users
```

Requires `users:read` permission.

```sh
curl http://localhost:3000/admin/users -H "$AUTH"
```

**Response**: `200 OK`

```json
[
  {
    "id": "550e8400-e29b-41d4-a716-446655440000",
    "did": "did:plc:admin",
    "is_super": true,
    "permissions": ["lexicons:create", "lexicons:read", "lexicons:delete", "records:read", "records:delete", "records:delete-collection", "script-variables:create", "script-variables:read", "script-variables:delete", "users:create", "users:read", "users:update", "users:delete", "api-keys:create", "api-keys:read", "api-keys:delete", "backfill:create", "backfill:read", "stats:read", "events:read"],
    "created_at": "2025-01-01T00:00:00Z",
    "last_used_at": "2025-01-02T12:00:00Z"
  }
]
```

### Get a user

```
GET /admin/users/{id}
```

Requires `users:read` permission.

```sh
curl http://localhost:3000/admin/users/550e8400-e29b-41d4-a716-446655440000 -H "$AUTH"
```

**Response**: `200 OK` with the same shape as a single item from the list response.

### Update user permissions

```
PATCH /admin/users/{id}/permissions
```

Requires `users:update` permission. You cannot grant permissions you don't have yourself, and you cannot modify the super user's permissions.

```sh
curl -X PATCH http://localhost:3000/admin/users/550e8400-e29b-41d4-a716-446655440000/permissions \
  -H "$AUTH" \
  -H "Content-Type: application/json" \
  -d '{
    "grant": ["lexicons:create", "lexicons:delete"],
    "revoke": ["records:delete"]
  }'
```

| Field    | Type     | Required | Description                    |
| -------- | -------- | -------- | ------------------------------ |
| `grant`  | string[] | no       | Permissions to add             |
| `revoke` | string[] | no       | Permissions to remove          |

**Response**: `200 OK` with the updated user object.

### Transfer super user

```
POST /admin/users/transfer-super
```

Only the current super user can call this endpoint. Transfers super user status to another existing user.

```sh
curl -X POST http://localhost:3000/admin/users/transfer-super \
  -H "$AUTH" \
  -H "Content-Type: application/json" \
  -d '{ "target_user_id": "550e8400-e29b-41d4-a716-446655440000" }'
```

| Field            | Type   | Required | Description                              |
| ---------------- | ------ | -------- | ---------------------------------------- |
| `target_user_id` | string | yes      | The ID of the user to receive super status |

**Response**: `200 OK`

### Delete a user

```
DELETE /admin/users/{id}
```

Requires `users:delete` permission. You cannot delete the super user or yourself.

```sh
curl -X DELETE http://localhost:3000/admin/users/550e8400-e29b-41d4-a716-446655440000 \
  -H "$AUTH"
```

**Response**: `204 No Content`

## Permissions

Each admin API endpoint requires a specific permission. See the [Permissions guide](../guides/permissions.md) for the full list of permissions and templates.

| Endpoint                              | Required Permission          |
| ------------------------------------- | ---------------------------- |
| `POST /admin/lexicons`                | `lexicons:create`            |
| `GET /admin/lexicons`                 | `lexicons:read`              |
| `GET /admin/lexicons/{id}`            | `lexicons:read`              |
| `DELETE /admin/lexicons/{id}`         | `lexicons:delete`            |
| `POST /admin/network-lexicons`        | `lexicons:create`            |
| `GET /admin/network-lexicons`         | `lexicons:read`              |
| `DELETE /admin/network-lexicons/{id}` | `lexicons:delete`            |
| `GET /admin/stats`                    | `stats:read`                 |
| `GET /admin/tap/stats`               | `stats:read`                 |
| `POST /admin/backfill`               | `backfill:create`            |
| `GET /admin/backfill/status`         | `backfill:read`              |
| `GET /admin/events`                  | `events:read`                |
| `POST /admin/api-keys`              | `api-keys:create`            |
| `GET /admin/api-keys`               | `api-keys:read`              |
| `DELETE /admin/api-keys/{id}`        | `api-keys:delete`            |
| `POST /admin/users`                  | `users:create`               |
| `GET /admin/users`                   | `users:read`                 |
| `GET /admin/users/{id}`             | `users:read`                 |
| `PATCH /admin/users/{id}/permissions`| `users:update`               |
| `DELETE /admin/users/{id}`           | `users:delete`               |
| `POST /admin/users/transfer-super`   | Super user only              |
| `GET /admin/script-variables`        | `script-variables:read`      |
| `POST /admin/script-variables`       | `script-variables:create`    |
| `DELETE /admin/script-variables/{key}`| `script-variables:delete`   |
