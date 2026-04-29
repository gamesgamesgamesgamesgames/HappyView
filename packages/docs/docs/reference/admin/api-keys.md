# API Keys

Manage API keys for programmatic access. See the [API Keys guide](../../guides/admin/api-keys.md) for usage details.

```sh
# All examples assume $TOKEN is an API key (hv_...)
AUTH="Authorization: Bearer $TOKEN"
```

## Create an API key

```
POST /admin/api-keys
```

Requires `api-keys:create` permission.

```sh
curl -X POST http://127.0.0.1:3000/admin/api-keys \
  -H "$AUTH" \
  -H "Content-Type: application/json" \
  -d '{
    "name": "CI Deploy",
    "permissions": ["lexicons:read", "lexicons:create", "backfill:create"]
  }'
```

| Field         | Type     | Required | Description                                                                           |
| ------------- | -------- | -------- | ------------------------------------------------------------------------------------- |
| `name`        | string   | yes      | A label to identify this key's usage                                                  |
| `permissions` | string[] | yes      | Permissions to grant the key (must be a subset of the creating user's own permissions) |

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

## List API keys

```
GET /admin/api-keys
```

Requires `api-keys:read` permission.

```sh
curl http://127.0.0.1:3000/admin/api-keys -H "$AUTH"
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

## Revoke an API key

```
DELETE /admin/api-keys/{id}
```

Requires `api-keys:delete` permission.

```sh
curl -X DELETE http://127.0.0.1:3000/admin/api-keys/550e8400-e29b-41d4-a716-446655440000 \
  -H "$AUTH"
```

Sets `revoked_at` on the key. The key remains in the database for audit purposes but can no longer authenticate.

**Response**: `204 No Content`
