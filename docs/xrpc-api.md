# XRPC API

HappyView dynamically registers XRPC endpoints based on uploaded lexicons. Query lexicons become `GET /xrpc/{nsid}` routes, procedure lexicons become `POST /xrpc/{nsid}` routes.

## Auth

- **Queries** (`GET /xrpc/{method}`): unauthenticated
- **Procedures** (`POST /xrpc/{method}`): require an AIP-issued `Authorization: Bearer <token>` header
- **getProfile**: requires auth
- **uploadBlob**: requires auth

---

## Fixed endpoints

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

---

## Dynamic query endpoints

Query endpoints are generated from lexicons with `type: "query"`. They support two modes depending on whether a `uri` parameter is provided.

### Single record

```
GET /xrpc/{method}?uri={at-uri}
```

```sh
curl "http://localhost:3000/xrpc/games.gamesgamesgamesgames.listGames?uri=at%3A%2F%2Fdid%3Aplc%3Aabc%2Fgames.gamesgamesgamesgames.game%2Fabc123"
```

**Response**: `200 OK`

```json
{
  "record": {
    "uri": "at://did:plc:abc/games.gamesgamesgamesgames.game/abc123",
    "$type": "games.gamesgamesgamesgames.game",
    "title": "My Game"
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
curl "http://localhost:3000/xrpc/games.gamesgamesgamesgames.listGames?limit=10&did=did:plc:abc"
```

**Response**: `200 OK`

```json
{
  "records": [
    {
      "uri": "at://did:plc:abc/games.gamesgamesgamesgames.game/abc123",
      "title": "My Game"
    }
  ],
  "cursor": "10"
}
```

The `cursor` field is present only when more records exist.

---

## Dynamic procedure endpoints

Procedure endpoints are generated from lexicons with `type: "procedure"`. HappyView auto-detects create vs update based on whether the request body contains a `uri` field.

### Create a record

```
POST /xrpc/{method}
```

When the body does **not** contain a `uri` field, a new record is created.

```sh
curl -X POST http://localhost:3000/xrpc/games.gamesgamesgamesgames.createGame \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{ "title": "My Game" }'
```

HappyView proxies this to the user's PDS as `com.atproto.repo.createRecord`, then indexes the created record locally.

### Update a record

When the body **contains** a `uri` field, the existing record is updated.

```sh
curl -X POST http://localhost:3000/xrpc/games.gamesgamesgamesgames.createGame \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "uri": "at://did:plc:abc/games.gamesgamesgamesgames.game/abc123",
    "title": "Updated Title"
  }'
```

HappyView proxies this to the user's PDS as `com.atproto.repo.putRecord`, then upserts the record locally.

**Response** for both: proxied from the user's PDS.
