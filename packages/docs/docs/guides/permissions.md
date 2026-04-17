# Permissions

HappyView uses a granular permission system to control access to the admin API. Each user has a set of permissions that determine which endpoints they can access. Permissions can be assigned individually, via templates, or both.

## Permission list

HappyView defines 20 permissions organized by category:

### Lexicons

| Permission | Description |
|---|---|
| `lexicons:create` | Upload and upsert lexicons (local and network) |
| `lexicons:read` | List and view lexicon details |
| `lexicons:delete` | Delete lexicons |

### Records

| Permission | Description |
|---|---|
| `records:read` | List and view indexed records |
| `records:delete` | Delete individual records |
| `records:delete-collection` | Bulk-delete all records in a collection |

### Script Variables

| Permission | Description |
|---|---|
| `script-variables:create` | Create and update script variables |
| `script-variables:read` | List script variables (values are masked) |
| `script-variables:delete` | Delete script variables |

### Users

| Permission | Description |
|---|---|
| `users:create` | Add new users |
| `users:read` | List and view user details |
| `users:update` | Modify user permissions |
| `users:delete` | Remove users |

### API Keys

| Permission | Description |
|---|---|
| `api-keys:create` | Create new API keys |
| `api-keys:read` | List API keys |
| `api-keys:delete` | Revoke API keys |

### Operations

| Permission | Description |
|---|---|
| `backfill:create` | Start backfill jobs |
| `backfill:read` | View backfill job status |
| `stats:read` | View record statistics |
| `events:read` | Query the event log |

## Permission templates

Templates are predefined sets of permissions that simplify user creation. Pass a `template` value when creating a user via `POST /admin/users`.

### Viewer

Read-only access. Can browse lexicons, records, stats, events, and user lists but cannot modify anything.

Includes: `lexicons:read`, `records:read`, `script-variables:read`, `users:read`, `api-keys:read`, `backfill:read`, `stats:read`, `events:read`

### Operator

Everything in Viewer, plus the ability to run backfill jobs and manage API keys.

Adds: `backfill:create`, `api-keys:create`, `api-keys:delete`

### Manager

Everything in Operator, plus the ability to manage lexicons, records, and script variables.

Adds: `lexicons:create`, `lexicons:delete`, `script-variables:create`, `script-variables:delete`, `records:delete`

### Full Access

All 20 permissions. Equivalent to granting every permission individually (but still not a super user).

## Super user

The super user is a special user created automatically when the first person logs in to a fresh HappyView instance. The super user:

- Has unrestricted access to all endpoints, regardless of which permissions are assigned
- Is the only user who can call `POST /admin/users/transfer-super`
- Cannot be deleted
- Cannot have their permissions modified by other users

There is always exactly one super user. Super status can be transferred to another user via the transfer endpoint.

## Escalation guards

HappyView prevents privilege escalation:

- When creating a user or API key, you can only grant permissions that you yourself have. Attempting to grant a permission you lack returns `403 Forbidden`.
- When updating a user's permissions, the same rule applies — you cannot grant permissions beyond your own.

## Self-modification guards

Users cannot modify their own account in destructive ways:

- You cannot delete yourself
- You cannot revoke your own permissions

These guards prevent accidental lockout.

## API key permissions

API keys have their own set of permissions, specified at creation time. The effective permissions of an API key are the **intersection** of:

1. The permissions assigned to the key
2. The permissions of the user who owns the key

This means if a user's permissions are later reduced, any API keys they created are also effectively reduced — even though the key's own permission list doesn't change.

For example, if a user with `lexicons:create` and `lexicons:read` creates a key with both permissions, and the user later loses `lexicons:create`, the key can only use `lexicons:read`.

## Managing permissions

### Via the dashboard

Go to **Settings > Users** to view and manage user permissions. Click on a user to see their current permissions and modify them. You can also assign templates when creating new users.

### Via the API

- `POST /admin/users` — create a user with a template or explicit permissions
- `PATCH /admin/users/{id}/permissions` — grant or revoke individual permissions
- `POST /admin/users/transfer-super` — transfer super user status (super user only)

See the [Admin API reference](../reference/admin-api.md#user-management) for full details.

## Next steps

- [Admin API reference](../reference/admin-api.md) — endpoint documentation with required permissions
- [API Keys](api-keys.md) — creating scoped API keys
- [Event Logs](event-logs.md) — permission-denied events are logged for auditing
