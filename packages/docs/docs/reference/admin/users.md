# Users

Manage admin users and their permissions. See the [Permissions guide](../../guides/admin/permissions.md) for available permissions and templates.

```sh
# All examples assume $TOKEN is an API key (hv_...)
AUTH="Authorization: Bearer $TOKEN"
```

## Create a user

```
POST /admin/users
```

Requires `users:create` permission. You cannot grant permissions you don't have yourself (escalation guard).

```sh
curl -X POST http://127.0.0.1:3000/admin/users \
  -H "$AUTH" \
  -H "Content-Type: application/json" \
  -d '{
    "did": "did:plc:newuser",
    "template": "operator"
  }'
```

| Field         | Type     | Required | Description                                                                        |
| ------------- | -------- | -------- | ---------------------------------------------------------------------------------- |
| `did`         | string   | yes      | The atproto DID of the user to add                                             |
| `template`    | string   | no       | Permission template: `viewer`, `operator`, `manager`, or `full_access`             |
| `permissions` | string[] | no       | Explicit list of permissions to grant (used instead of or in addition to `template`) |

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

## List users

```
GET /admin/users
```

Requires `users:read` permission.

```sh
curl http://127.0.0.1:3000/admin/users -H "$AUTH"
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

## Get a user

```
GET /admin/users/{id}
```

Requires `users:read` permission.

```sh
curl http://127.0.0.1:3000/admin/users/550e8400-e29b-41d4-a716-446655440000 -H "$AUTH"
```

**Response**: `200 OK` with the same shape as a single item from the list response.

## Update user permissions

```
PATCH /admin/users/{id}/permissions
```

Requires `users:update` permission. You cannot grant permissions you don't have yourself, and you cannot modify the super user's permissions.

```sh
curl -X PATCH http://127.0.0.1:3000/admin/users/550e8400-e29b-41d4-a716-446655440000/permissions \
  -H "$AUTH" \
  -H "Content-Type: application/json" \
  -d '{
    "grant": ["lexicons:create", "lexicons:delete"],
    "revoke": ["records:delete"]
  }'
```

| Field    | Type     | Required | Description           |
| -------- | -------- | -------- | --------------------- |
| `grant`  | string[] | no       | Permissions to add    |
| `revoke` | string[] | no       | Permissions to remove |

**Response**: `200 OK` with the updated user object.

## Transfer super user

```
POST /admin/users/transfer-super
```

Only the current super user can call this endpoint. Transfers super user status to another existing user.

```sh
curl -X POST http://127.0.0.1:3000/admin/users/transfer-super \
  -H "$AUTH" \
  -H "Content-Type: application/json" \
  -d '{ "target_user_id": "550e8400-e29b-41d4-a716-446655440000" }'
```

| Field            | Type   | Required | Description                                |
| ---------------- | ------ | -------- | ------------------------------------------ |
| `target_user_id` | string | yes      | The ID of the user to receive super status |

**Response**: `200 OK`

## Delete a user

```
DELETE /admin/users/{id}
```

Requires `users:delete` permission. You cannot delete the super user or yourself.

```sh
curl -X DELETE http://127.0.0.1:3000/admin/users/550e8400-e29b-41d4-a716-446655440000 \
  -H "$AUTH"
```

**Response**: `204 No Content`
