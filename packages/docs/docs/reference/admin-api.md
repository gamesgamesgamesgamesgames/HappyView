# Admin API

The admin API lets you manage lexicons, monitor records, run backfill jobs, and control user access. All endpoints live under `/admin` and require authentication from a DID that exists in the `users` table, with the appropriate [permissions](../guides/permissions.md) for the endpoint being called. You can also manage all of this through the [web dashboard](../getting-started/dashboard.md).

## Auth

The admin API supports three authentication methods:

1. **Session cookie** (web UI) — Set during the OAuth login flow. The signed cookie contains the user's DID.
2. **API keys** — read/write tokens starting with `hv_`, passed as `Authorization: Bearer hv_...`. See the [API Keys guide](../guides/api-keys.md) for details.
3. **Service auth JWT** — AT Protocol inter-service authentication via signed JWTs.

In all cases the resolved DID is checked against the `users` table, and the user's permissions are loaded to authorize the request.

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
| `401 Unauthorized` | Missing or invalid session cookie, API key, or service auth JWT                                                |
| `403 Forbidden`    | Authenticated DID is not in the users table, or user lacks the required permission                             |
| `404 Not Found`    | Lexicon, user, or backfill job not found                                                                       |

```sh
# All examples assume $TOKEN is an API key (hv_...)
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

Network lexicons are fetched from the AT Protocol network via DNS TXT resolution and kept updated via the Jetstream subscription. See [Lexicons - Network lexicons](../guides/lexicons.md#network-lexicons) for background.

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

HappyView records an audit trail of system events: lexicon changes, record operations, Lua script executions and errors, user actions, backfill jobs, and Jetstream connectivity. See the [Event Logs guide](../guides/event-logs.md) for details on event types and retention.

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

## Labelers

Manage external labeler subscriptions. See the [Labelers guide](../guides/labelers.md) for background.

### Add a labeler

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

| Field | Type   | Required | Description            |
| ----- | ------ | -------- | ---------------------- |
| `did` | string | yes      | The labeler's AT Protocol DID |

**Response**: `201 Created` (empty body)

### List labelers

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

| Field        | Type         | Description                                      |
| ------------ | ------------ | ------------------------------------------------ |
| `did`        | string       | The labeler's DID                                |
| `status`     | string       | `active` or `paused`                             |
| `cursor`     | number\|null | Last processed event cursor (null if never synced) |
| `created_at` | string       | ISO 8601 creation timestamp                      |
| `updated_at` | string       | ISO 8601 last-updated timestamp                  |

### Update a labeler

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

| Field    | Type   | Required | Description                  |
| -------- | ------ | -------- | ---------------------------- |
| `status` | string | yes      | New status: `active` or `paused` |

**Response**: `200 OK`

### Delete a labeler

```
DELETE /admin/labelers/{did}
```

Requires `labelers:delete` permission. Removes the subscription and all labels emitted by this labeler.

```sh
curl -X DELETE http://localhost:3000/admin/labelers/did:plc:ar7c4by46qjdydhdevvrndac \
  -H "$AUTH"
```

**Response**: `204 No Content`

## Instance Settings

Instance settings are key/value entries used to override environment-variable defaults at runtime (for example, the application name, terms-of-service URL, privacy policy URL, and uploaded logo). Settings stored here take precedence over the corresponding environment variables. All endpoints require the `settings:manage` permission.

### List settings

```
GET /admin/settings
```

```sh
curl http://localhost:3000/admin/settings -H "$AUTH"
```

Returns all key/value pairs stored in the `instance_settings` table.

### Upsert a setting

```
PUT /admin/settings/{key}
```

```sh
curl -X PUT http://localhost:3000/admin/settings/app_name \
  -H "$AUTH" \
  -H "Content-Type: application/json" \
  -d '{ "value": "My HappyView" }'
```

### Delete a setting

```
DELETE /admin/settings/{key}
```

Removes the override; the corresponding environment variable (if any) takes effect again.

### Upload / delete logo

```
PUT /admin/settings/logo
DELETE /admin/settings/logo
```

`PUT` accepts a binary image body and stores it as the instance logo (served via the public dashboard). `DELETE` removes the stored logo.

## Domain Management

Manage the domains a HappyView instance serves. Each domain gets its own AT Protocol OAuth client identity. The primary domain is auto-seeded from `PUBLIC_URL` on first boot. All endpoints require the `settings:manage` permission.

### List domains

```
GET /admin/domains
```

```sh
curl http://localhost:3000/admin/domains -H "$AUTH"
```

**Response**: `200 OK`

```json
[
  {
    "id": "550e8400-e29b-41d4-a716-446655440000",
    "url": "https://gamesgamesgamesgames.games",
    "is_primary": true,
    "created_at": "2026-04-16T00:00:00Z",
    "updated_at": "2026-04-16T00:00:00Z"
  }
]
```

### Add a domain

```
POST /admin/domains
```

```sh
curl -X POST http://localhost:3000/admin/domains \
  -H "$AUTH" \
  -H "Content-Type: application/json" \
  -d '{ "url": "https://api.cartridge.dev" }'
```

| Field | Type   | Required | Description                                                                                                                          |
| ----- | ------ | -------- | ------------------------------------------------------------------------------------------------------------------------------------ |
| `url` | string | yes      | Valid origin (scheme + host, no path or trailing slash). Must be `https` unless `PUBLIC_URL` is a loopback address. |

Returns `400 Bad Request` if the URL is invalid or already registered.

**Response**: `201 Created`

```json
{
  "id": "550e8400-e29b-41d4-a716-446655440001",
  "url": "https://api.cartridge.dev",
  "is_primary": false,
  "created_at": "2026-04-16T00:00:00Z",
  "updated_at": "2026-04-16T00:00:00Z"
}
```

Side effects: builds an OAuth client for the domain, updates the in-memory domain cache.

### Remove a domain

```
DELETE /admin/domains/{id}
```

```sh
curl -X DELETE http://localhost:3000/admin/domains/550e8400-e29b-41d4-a716-446655440001 \
  -H "$AUTH"
```

Returns `400 Bad Request` if the domain is primary — set a different domain as primary first. Returns `404 Not Found` if the domain doesn't exist.

**Response**: `204 No Content`

Side effects: removes the domain's OAuth client and cache entry.

### Set primary domain

```
POST /admin/domains/{id}/primary
```

```sh
curl -X POST http://localhost:3000/admin/domains/550e8400-e29b-41d4-a716-446655440001/primary \
  -H "$AUTH"
```

Sets the target domain as the primary. Unsets the current primary in a single operation. Returns `404 Not Found` if the domain doesn't exist.

**Response**: `204 No Content`

Side effects: updates the in-memory cache and the OAuth client registry's primary client reference.

## Script Variables

Script variables are encrypted key/value pairs available to Lua scripts via the `vars` global. Use them for secrets like API tokens.

### List script variables

```
GET /admin/script-variables
```

Requires `script-variables:read`. Returns a list of variable keys (values are not returned).

### Upsert a script variable

```
POST /admin/script-variables
```

Requires `script-variables:create`.

```sh
curl -X POST http://localhost:3000/admin/script-variables \
  -H "$AUTH" \
  -H "Content-Type: application/json" \
  -d '{ "key": "ALGOLIA_API_KEY", "value": "..." }'
```

The value is encrypted at rest using `TOKEN_ENCRYPTION_KEY`.

### Delete a script variable

```
DELETE /admin/script-variables/{key}
```

Requires `script-variables:delete`.

## API Clients

API clients represent third-party applications that call HappyView's XRPC endpoints. **Every XRPC request** — including unauthenticated queries — must identify itself with a registered client via the `X-Client-Key` header (or session cookie, or `client_key` query param). The client key is HappyView's rate-limit bucket and caller identity; a request without one gets `401 Unauthorized`.

Each client has an `hvc_`-prefixed client key and an `hvs_`-prefixed client secret. The secret is only returned once (at creation) and is sha256-hashed in the database. Server-to-server callers pass the secret as `X-Client-Secret`; browser callers rely on the `Origin` header matching the client's registered `client_uri`. Both checks currently log warnings on mismatch rather than rejecting the request, but the rate-limit bucket is applied either way. See [Authentication — XRPC](../getting-started/authentication.md#xrpc-api-client-identification) for the client-side view, and the [API Keys guide](../guides/api-keys.md) for how admin API keys differ from API clients.

### List API clients

```
GET /admin/api-clients
```

Requires `api-clients:view`. Returns clients ordered by `created_at` descending. Secrets are never returned.

```sh
curl http://localhost:3000/admin/api-clients -H "$AUTH"
```

**Response**: `200 OK`

```json
[
  {
    "id": "01J9...",
    "client_key": "hvc_a1b2c3...",
    "name": "My Game Client",
    "client_id_url": "https://example.com/client-metadata.json",
    "client_uri": "https://example.com",
    "redirect_uris": ["https://example.com/callback"],
    "scopes": "atproto",
    "rate_limit_capacity": 200,
    "rate_limit_refill_rate": 5.0,
    "is_active": true,
    "created_by": "did:plc:...",
    "created_at": "2026-04-13T12:00:00Z",
    "updated_at": "2026-04-13T12:00:00Z"
  }
]
```

### Create an API client

```
POST /admin/api-clients
```

Requires `api-clients:create`. Generates a fresh `client_key` and `client_secret`. **The secret is only returned in this response** — store it immediately.

```sh
curl -X POST http://localhost:3000/admin/api-clients \
  -H "$AUTH" \
  -H "Content-Type: application/json" \
  -d '{
    "name": "My Game Client",
    "client_id_url": "https://example.com/client-metadata.json",
    "client_uri": "https://example.com",
    "redirect_uris": ["https://example.com/callback"],
    "scopes": "atproto",
    "rate_limit_capacity": 200,
    "rate_limit_refill_rate": 5.0
  }'
```

| Field                    | Type     | Required | Description                                                                            |
| ------------------------ | -------- | -------- | -------------------------------------------------------------------------------------- |
| `name`                   | string   | yes      | Human-readable display name                                                            |
| `client_id_url`          | string   | yes      | URL to the client's published OAuth client metadata document                           |
| `client_uri`             | string   | yes      | The client's home/landing URL                                                          |
| `redirect_uris`          | string[] | yes      | Allowed OAuth redirect URIs                                                            |
| `scopes`                 | string   | no       | Space-separated OAuth scopes (default `"atproto"`)                                     |
| `rate_limit_capacity`    | integer  | no       | Per-client token bucket capacity. Falls back to `DEFAULT_RATE_LIMIT_CAPACITY` if unset |
| `rate_limit_refill_rate` | number   | no       | Tokens added per second. Falls back to `DEFAULT_RATE_LIMIT_REFILL_RATE` if unset       |

**Response**: `201 Created`

```json
{
  "id": "01J9...",
  "client_key": "hvc_a1b2c3...",
  "client_secret": "hvs_d4e5f6...",
  "name": "My Game Client",
  "client_id_url": "https://example.com/client-metadata.json"
}
```

The new client is immediately registered with the OAuth registry and rate limiter, so it can authenticate without restarting HappyView.

### Get an API client

```
GET /admin/api-clients/{id}
```

Requires `api-clients:view`. Returns the same `ApiClientSummary` shape as the list endpoint, or `404 Not Found`.

### Update an API client

```
PUT /admin/api-clients/{id}
```

Requires `api-clients:edit`. All fields are optional — only provided fields are changed. Updating either rate-limit field re-registers the client with the rate limiter using the new values.

| Field                    | Type     | Description                                                              |
| ------------------------ | -------- | ------------------------------------------------------------------------ |
| `name`                   | string   | New display name                                                         |
| `client_uri`             | string   | New home URL                                                             |
| `redirect_uris`          | string[] | Replace the allowed redirect URIs                                        |
| `scopes`                 | string   | Replace the OAuth scopes                                                 |
| `rate_limit_capacity`    | integer  | New bucket capacity. Pass `null` to clear the override                   |
| `rate_limit_refill_rate` | number   | New refill rate. Pass `null` to clear the override                       |
| `is_active`              | boolean  | Disable (`false`) or re-enable (`true`) the client without deleting it   |

**Response**: `204 No Content`

The OAuth registry is updated in place. The `client_id_url` is immutable — to change it, delete and recreate the client.

### Delete an API client

```
DELETE /admin/api-clients/{id}
```

Requires `api-clients:delete`. Removes the client from the OAuth registry, the rate limiter, and the client identity store.

**Response**: `204 No Content`

## Plugins

Plugins extend HappyView with WebAssembly modules sourced from the [official plugin registry](../guides/plugins.md) or any URL serving a `manifest.json`. Most endpoints take a plugin manifest URL and load (or reload) the plugin in place — no restart needed. Encrypted plugin secrets require `TOKEN_ENCRYPTION_KEY` to be configured.

### List installed plugins

```
GET /admin/plugins
```

Requires `plugins:read`. Returns every loaded plugin with its source, required secrets, configuration status, and any pending updates from the official registry cache.

```sh
curl http://localhost:3000/admin/plugins -H "$AUTH"
```

**Response**: `200 OK`

```json
{
  "encryption_configured": true,
  "plugins": [
    {
      "id": "steam",
      "name": "Steam",
      "version": "1.2.0",
      "source": "url",
      "url": "https://example.com/plugins/steam/manifest.json",
      "sha256": null,
      "enabled": true,
      "auth_type": "openid",
      "required_secrets": [
        {
          "key": "PLUGIN_STEAM_API_KEY",
          "name": "Steam Web API Key",
          "description": "Get your API key at steamcommunity.com/dev/apikey"
        }
      ],
      "secrets_configured": true,
      "loaded_at": null,
      "update_available": false,
      "latest_version": "1.2.0",
      "pending_releases": []
    }
  ]
}
```

`secrets_configured` is `true` if the plugin has no required secrets, or if a row exists for it in `plugin_configs`. `update_available` and `pending_releases` are populated from the cached official registry — call `POST /admin/plugins/{id}/check-update` to refresh them.

### Preview a plugin before installing

```
POST /admin/plugins/preview
```

Requires `plugins:create`. Fetches and parses a manifest without installing the plugin, so the dashboard can show what it would register.

```sh
curl -X POST http://localhost:3000/admin/plugins/preview \
  -H "$AUTH" \
  -H "Content-Type: application/json" \
  -d '{ "url": "https://example.com/plugins/steam/manifest.json" }'
```

**Response**: `200 OK`

```json
{
  "id": "steam",
  "name": "Steam",
  "version": "1.2.0",
  "description": "Import your Steam game library and playtime data.",
  "icon_url": "https://example.com/steam-icon.png",
  "auth_type": "openid",
  "required_secrets": [
    { "key": "PLUGIN_STEAM_API_KEY", "name": "Steam Web API Key", "description": "..." }
  ],
  "manifest_url": "https://example.com/plugins/steam/manifest.json",
  "wasm_url": "https://example.com/plugins/steam/steam.wasm"
}
```

Returns `400 Bad Request` if the manifest can't be fetched or parsed.

### Install a plugin

```
POST /admin/plugins
```

Requires `plugins:create`. Fetches the manifest, downloads the WASM, registers the plugin, and persists it.

```sh
curl -X POST http://localhost:3000/admin/plugins \
  -H "$AUTH" \
  -H "Content-Type: application/json" \
  -d '{
    "url": "https://example.com/plugins/steam/manifest.json",
    "sha256": "abc123..."
  }'
```

| Field    | Type   | Required | Description                                                                                  |
| -------- | ------ | -------- | -------------------------------------------------------------------------------------------- |
| `url`    | string | yes      | URL to the plugin's `manifest.json`                                                          |
| `sha256` | string | no       | Optional sha256 of the WASM binary. If provided, install fails when the downloaded hash mismatches |

**Response**: `200 OK` returning the same `PluginSummary` shape as the list endpoint. `secrets_configured` will be `false` if the plugin requires any secrets — call `PUT /admin/plugins/{id}/secrets` to configure them before the plugin can run.

### List official plugins

```
GET /admin/plugins/official
```

Requires `plugins:read`. Returns the cached catalog of plugins from the official registry. The cache is refreshed periodically by the server; use `POST /admin/plugins/{id}/check-update` to force-refresh a single entry.

**Response**: `200 OK`

```json
{
  "last_refreshed_at": "2026-04-13T11:00:00Z",
  "plugins": [
    {
      "id": "steam",
      "name": "Steam",
      "description": "Import your Steam game library and playtime data.",
      "icon_url": "https://example.com/steam-icon.png",
      "latest_version": "1.2.0",
      "manifest_url": "https://example.com/plugins/steam/manifest.json"
    }
  ]
}
```

### Remove a plugin

```
DELETE /admin/plugins/{id}
```

Requires `plugins:delete`. Unregisters the plugin from the runtime and deletes its row from the `plugins` table. Plugin secrets in `plugin_configs` are not removed automatically — they're available again if you reinstall the same plugin.

**Response**: `204 No Content`. Returns `404 Not Found` if no plugin with that id is loaded.

### Reload a plugin

```
POST /admin/plugins/{id}/reload
```

Requires `plugins:create`. Re-fetches the plugin from its current source URL and re-registers it. Useful after publishing a new version of a plugin you host yourself.

The body is optional. To point the plugin at a new URL, pass:

```json
{ "url": "https://example.com/plugins/steam/manifest.json" }
```

When a new URL is provided, the stored `sha256` is cleared (the new version has its own hash). File-based plugins cannot be reloaded via this endpoint and return `400 Bad Request`.

**Response**: `200 OK` with the refreshed `PluginSummary`.

### Check for plugin updates

```
POST /admin/plugins/{id}/check-update
```

Requires `plugins:create`. Forces a cache refresh for one plugin from the official registry, then returns the updated `PluginSummary` with `update_available`, `latest_version`, and `pending_releases` reflecting the latest catalog state.

**Response**: `200 OK` with a `PluginSummary`.

### Get plugin secrets

```
GET /admin/plugins/{id}/secrets
```

Requires `plugins:read`. Returns the plugin's configured secrets with values masked (last 4 characters shown for values longer than 8 characters, otherwise fully masked). Requires `TOKEN_ENCRYPTION_KEY` to be configured.

**Response**: `200 OK`

```json
{
  "plugin_id": "steam",
  "secrets": {
    "PLUGIN_STEAM_API_KEY": "********ABCD"
  }
}
```

### Update plugin secrets

```
PUT /admin/plugins/{id}/secrets
```

Requires `plugins:create`. Encrypts the provided secret values with `TOKEN_ENCRYPTION_KEY` (AES-256-GCM) and upserts them into `plugin_configs`.

```sh
curl -X PUT http://localhost:3000/admin/plugins/steam/secrets \
  -H "$AUTH" \
  -H "Content-Type: application/json" \
  -d '{
    "secrets": {
      "PLUGIN_STEAM_API_KEY": "your-new-api-key"
    }
  }'
```

Special handling:

- Values starting with `********` are treated as masked placeholders and the existing encrypted value is preserved (so you can `GET` then `PUT` without re-typing every secret).
- Empty string values are not stored — use them to clear a secret.

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
| `POST /admin/labelers`               | `labelers:create`            |
| `GET /admin/labelers`                | `labelers:read`              |
| `PATCH /admin/labelers/{did}`        | `labelers:create`            |
| `DELETE /admin/labelers/{did}`       | `labelers:delete`            |
| `GET /admin/settings`                | `settings:manage`            |
| `PUT /admin/settings/{key}`          | `settings:manage`            |
| `DELETE /admin/settings/{key}`       | `settings:manage`            |
| `PUT /admin/settings/logo`           | `settings:manage`            |
| `DELETE /admin/settings/logo`        | `settings:manage`            |
| `GET /admin/plugins`                 | `plugins:read`               |
| `POST /admin/plugins`                | `plugins:create`             |
| `POST /admin/plugins/preview`        | `plugins:read`               |
| `GET /admin/plugins/official`        | `plugins:read`               |
| `DELETE /admin/plugins/{id}`         | `plugins:delete`             |
| `POST /admin/plugins/{id}/reload`    | `plugins:create`             |
| `POST /admin/plugins/{id}/check-update` | `plugins:read`            |
| `GET /admin/plugins/{id}/secrets`    | `plugins:read`               |
| `PUT /admin/plugins/{id}/secrets`    | `plugins:create`             |
| `GET /admin/domains`                 | `settings:manage`            |
| `POST /admin/domains`                | `settings:manage`            |
| `DELETE /admin/domains/{id}`         | `settings:manage`            |
| `POST /admin/domains/{id}/primary`   | `settings:manage`            |
| `GET /admin/api-clients`             | `api-clients:view`           |
| `POST /admin/api-clients`            | `api-clients:create`         |
| `GET /admin/api-clients/{id}`        | `api-clients:view`           |
| `PUT /admin/api-clients/{id}`        | `api-clients:edit`           |
| `DELETE /admin/api-clients/{id}`     | `api-clients:delete`         |
