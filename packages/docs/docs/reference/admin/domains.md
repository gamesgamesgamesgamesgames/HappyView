# Admin API: Domains

Manage the domains a HappyView instance serves. Each domain gets its own AT Protocol OAuth client identity. The primary domain is auto-seeded from `PUBLIC_URL` on first boot. All endpoints require the `settings:manage` permission.

```sh
# All examples assume $TOKEN is an API key (hv_...)
AUTH="Authorization: Bearer $TOKEN"
```

## List domains

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

## Add a domain

```
POST /admin/domains
```

```sh
curl -X POST http://localhost:3000/admin/domains \
  -H "$AUTH" \
  -H "Content-Type: application/json" \
  -d '{ "url": "https://api.cartridge.dev" }'
```

| Field | Type   | Required | Description                                                                                                        |
| ----- | ------ | -------- | ------------------------------------------------------------------------------------------------------------------ |
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

## Remove a domain

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

## Set primary domain

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
