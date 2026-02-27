# XRPC API

[XRPC](https://atproto.com/specs/xrpc) is the HTTP-based RPC protocol used by the AT Protocol. HappyView dynamically registers XRPC endpoints based on your uploaded [lexicons](../guides/lexicons.md): query lexicons become `GET /xrpc/{nsid}` routes, procedure lexicons become `POST /xrpc/{nsid}` routes.

If a query or procedure lexicon has a [Lua script](../guides/scripting.md) attached, the script handles the request. Otherwise, HappyView uses built-in default behavior (described below).

## Auth

- **Queries** (`GET /xrpc/{method}`): unauthenticated
- **Procedures** (`POST /xrpc/{method}`): require an AIP-issued `Authorization: Bearer <token>` header
- **getProfile**: requires auth
- **uploadBlob**: requires auth

## Fixed endpoints

These endpoints are always available regardless of which lexicons are loaded.

### Health check

```
GET /health
```

```sh
curl http://localhost:3000/health
```

**Response**: `200 OK` with body `ok`

### Get profile

```
GET /xrpc/app.bsky.actor.getProfile
```

Returns the authenticated user's profile, resolved from their PDS via PLC directory lookup.

```sh
curl http://localhost:3000/xrpc/app.bsky.actor.getProfile \
  -H "Authorization: Bearer $TOKEN"
```

**Response**: `200 OK`

```json
{
  "did": "did:plc:abc123",
  "handle": "user.bsky.social",
  "displayName": "User Name",
  "description": "Bio text",
  "avatarURL": "https://pds.example.com/xrpc/com.atproto.sync.getBlob?did=did:plc:abc123&cid=bafyabc"
}
```

### Upload blob

```
POST /xrpc/com.atproto.repo.uploadBlob
```

Proxies a blob upload to the authenticated user's PDS. Maximum size: 50MB.

```sh
curl -X POST http://localhost:3000/xrpc/com.atproto.repo.uploadBlob \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: image/png" \
  --data-binary @image.png
```

**Response**: proxied from the user's PDS.

## Dynamic query endpoints

Query endpoints are generated from lexicons with `type: "query"`. Without a [Lua script](../guides/scripting.md), they support two built-in modes depending on whether a `uri` parameter is provided.

### Single record

```
GET /xrpc/{method}?uri={at-uri}
```

```sh
curl "http://localhost:3000/xrpc/xyz.statusphere.listStatuses?uri=at%3A%2F%2Fdid%3Aplc%3Aabc%2Fxyz.statusphere.status%2Fabc123"
```

**Response**: `200 OK`

```json
{
  "record": {
    "uri": "at://did:plc:abc/xyz.statusphere.status/abc123",
    "$type": "xyz.statusphere.status",
    "status": "\ud83d\ude0a",
    "createdAt": "2025-01-01T12:00:00Z"
  }
}
```

Media blobs are automatically enriched with a `url` field pointing to the user's PDS.

### List records

```
GET /xrpc/{method}?limit=20&cursor=0&did=optional
```

| Param | Type | Default | Description |
|-------|------|---------|-------------|
| `limit` | integer | 20 | Max records to return (max 100) |
| `cursor` | string | `0` | Pagination cursor (opaque, pass from previous response) |
| `did` | string | --- | Filter records by DID |

```sh
curl "http://localhost:3000/xrpc/xyz.statusphere.listStatuses?limit=10&did=did:plc:abc"
```

**Response**: `200 OK`

```json
{
  "records": [
    {
      "uri": "at://did:plc:abc/xyz.statusphere.status/abc123",
      "status": "\ud83d\ude0a",
      "createdAt": "2025-01-01T12:00:00Z"
    }
  ],
  "cursor": "10"
}
```

The `cursor` field is present only when more records exist.

## Dynamic procedure endpoints

Procedure endpoints are generated from lexicons with `type: "procedure"`. Without a [Lua script](../guides/scripting.md), HappyView auto-detects create vs update based on whether the request body contains a `uri` field.

### Create a record

```
POST /xrpc/{method}
```

When the body does **not** contain a `uri` field, a new record is created.

```sh
curl -X POST http://localhost:3000/xrpc/xyz.statusphere.setStatus \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{ "status": "\ud83d\ude0a", "createdAt": "2025-01-01T12:00:00Z" }'
```

HappyView proxies this to the user's PDS as `com.atproto.repo.createRecord`, then indexes the created record locally.

### Update a record

When the body **contains** a `uri` field, the existing record is updated.

```sh
curl -X POST http://localhost:3000/xrpc/xyz.statusphere.setStatus \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "uri": "at://did:plc:abc/xyz.statusphere.status/abc123",
    "status": "\ud83c\udf1f",
    "createdAt": "2025-01-01T13:00:00Z"
  }'
```

HappyView proxies this to the user's PDS as `com.atproto.repo.putRecord`, then upserts the record locally.

**Response** for both: proxied from the user's PDS.

## Errors

All error responses return JSON with an `error` field:

```json
{
  "error": "description of what went wrong"
}
```

| Status | Meaning | Common causes |
|--------|---------|---------------|
| `400 Bad Request` | Invalid input | Missing required fields, malformed JSON, invalid AT URI |
| `401 Unauthorized` | Authentication failed | Missing or invalid Bearer token. See [AIP documentation](https://github.com/graze-social/aip) for token issues |
| `404 Not Found` | Method or record not found | XRPC method has no matching lexicon, or the requested record doesn't exist |
| `500 Internal Server Error` | Server-side failure | Lua script error, database error, or upstream PDS failure |

### Lua script errors

When a Lua script fails, the response is `500` with one of:

- `{"error": "script execution failed"}`: syntax error, runtime error, or missing `handle()` function
- `{"error": "script exceeded execution time limit"}`: the script hit the 1,000,000 instruction limit

The full error details are logged server-side but not exposed to the client. See [Lua Scripting - Debugging](../guides/scripting.md#debugging) for how to diagnose script issues.

### PDS errors

When a procedure proxies a write to the user's PDS and the PDS returns an error, HappyView forwards the PDS response status code and body directly to the client.

## Next steps

- [Lua Scripting](../guides/scripting.md): Override the default query and procedure behavior with custom logic
- [Lexicons](../guides/lexicons.md): Understand how lexicons generate these endpoints
- [Admin API](admin-api.md): Manage lexicons and monitor your instance
