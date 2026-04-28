# Third-Party API Clients

Third-party applications can manage their own API clients via the `dev.happyview.*` XRPC endpoints. A third-party client is always tied to exactly one parent — the admin-created top-level API client whose DPoP session made the request. Only one level of nesting is allowed; third-party clients cannot create further children. Each third-party client gets its own rate limit bucket with instance default settings.

All endpoints use [DPoP authentication](../../getting-started/authentication.md#authenticating-users-for-procedures). See the [admin API client docs](../admin/api-clients.md) for managing clients through the admin API, and the [API Clients guide](../../guides/features/api-clients.md) for how API clients work.

:::note
Only top-level API clients can call these endpoints. Third-party (child) clients receive `401 Unauthorized` or `403 Forbidden`.
:::

## Authentication

All requests require three headers:

| Header          | Value                                                        |
| --------------- | ------------------------------------------------------------ |
| `Authorization` | `DPoP <access_token>`                                        |
| `DPoP`          | A DPoP proof JWT (method matches the HTTP method, `htu` is scheme + host + path, no query string) |
| `X-Client-Key`  | The parent client's `client_key`                             |

The access token must belong to a valid DPoP session for the parent client.

## List clients

```
GET /xrpc/dev.happyview.listApiClients
```

Returns all API clients owned by the authenticated user.

**Response**: `200 OK`

```json
{
  "clients": [
    {
      "id": "550e8400-e29b-41d4-a716-446655440000",
      "clientKey": "hvc_a1b2c3d4e5f6...",
      "name": "My App",
      "clientIdUrl": "https://myapp.example.com/client-metadata.json",
      "clientUri": "https://myapp.example.com",
      "redirectUris": ["https://myapp.example.com/callback"],
      "clientType": "confidential",
      "scopes": "atproto",
      "allowedOrigins": [],
      "isActive": true,
      "createdAt": "2026-04-28T12:00:00Z"
    }
  ]
}
```

## Get a client

```
GET /xrpc/dev.happyview.getApiClient?id=<client_id>
```

| Parameter | Type   | Required | Description       |
| --------- | ------ | -------- | ----------------- |
| `id`      | string | yes      | The client's UUID |

**Response**: `200 OK`

```json
{
  "client": {
    "id": "550e8400-e29b-41d4-a716-446655440000",
    "clientKey": "hvc_a1b2c3d4e5f6...",
    "name": "My App",
    "clientIdUrl": "https://myapp.example.com/client-metadata.json",
    "clientUri": "https://myapp.example.com",
    "redirectUris": ["https://myapp.example.com/callback"],
    "clientType": "confidential",
    "scopes": "atproto",
    "allowedOrigins": [],
    "isActive": true,
    "createdAt": "2026-04-28T12:00:00Z"
  }
}
```

Returns `404` if the client doesn't exist or isn't owned by the authenticated user.

## Create a client

```
POST /xrpc/dev.happyview.createApiClient
```

```sh
curl -X POST https://happyview.example.com/xrpc/dev.happyview.createApiClient \
  -H "X-Client-Key: hvc_parent_key" \
  -H "Authorization: DPoP eyJhbG..." \
  -H "DPoP: eyJhbG..." \
  -H "Content-Type: application/json" \
  -d '{
    "name": "My Third-Party App",
    "clientIdUrl": "https://myapp.example.com/client-metadata.json",
    "clientUri": "https://myapp.example.com",
    "redirectUris": ["https://myapp.example.com/callback"],
    "clientType": "confidential"
  }'
```

| Field             | Type     | Required | Description                                                    |
| ----------------- | -------- | -------- | -------------------------------------------------------------- |
| `name`            | string   | yes      | Display name for the client                                    |
| `clientIdUrl`     | string   | yes      | Unique OAuth client ID URL                                     |
| `clientUri`       | string   | yes      | The client's homepage URL                                      |
| `redirectUris`    | string[] | yes      | OAuth redirect URIs                                            |
| `scopes`          | string   | no       | Space-separated OAuth scopes (default `"atproto"`)             |
| `clientType`      | string   | no       | `"confidential"` or `"public"` (default `"confidential"`)     |
| `allowedOrigins`  | string[] | no       | CORS allowed origins (relevant for public clients)             |

**Response**: `201 Created`

```json
{
  "client": {
    "id": "550e8400-e29b-41d4-a716-446655440000",
    "clientKey": "hvc_a1b2c3d4e5f6...",
    "name": "My Third-Party App",
    "clientIdUrl": "https://myapp.example.com/client-metadata.json",
    "clientUri": "https://myapp.example.com",
    "redirectUris": ["https://myapp.example.com/callback"],
    "clientType": "confidential",
    "scopes": "atproto",
    "allowedOrigins": [],
    "isActive": true,
    "createdAt": "2026-04-28T12:00:00Z"
  },
  "clientSecret": "hvs_f6e5d4c3b2a1..."
}
```

The `clientSecret` is only present for confidential clients and is only returned in this response. It is stored as a SHA-256 hash and cannot be retrieved again.

## Delete a client

```
POST /xrpc/dev.happyview.deleteApiClient
```

```sh
curl -X POST https://happyview.example.com/xrpc/dev.happyview.deleteApiClient \
  -H "X-Client-Key: hvc_parent_key" \
  -H "Authorization: DPoP eyJhbG..." \
  -H "DPoP: eyJhbG..." \
  -H "Content-Type: application/json" \
  -d '{ "id": "550e8400-e29b-41d4-a716-446655440000" }'
```

| Field | Type   | Required | Description       |
| ----- | ------ | -------- | ----------------- |
| `id`  | string | yes      | The client's UUID |

**Response**: `200 OK` with `{}`

Returns `404` if the client doesn't exist or isn't owned by the authenticated user. Deleting a client cascades to all its children.

## Errors

| Status | Error                                     | Cause                                                            |
| ------ | ----------------------------------------- | ---------------------------------------------------------------- |
| 400    | `Invalid client_type`                     | `client_type` is not `"confidential"` or `"public"`              |
| 400    | `invalid request body`                    | Missing required fields or malformed JSON                        |
| 401    | `requires DPoP authentication`            | `Authorization` header is missing or doesn't use the DPoP scheme |
| 401    | `requires an API client key`              | `X-Client-Key` header is absent                                  |
| 401    | `token_expired`                           | The access token has expired                                     |
| 401    | `Invalid client`                          | `X-Client-Key` doesn't match a known client                     |
| 401    | `child clients cannot manage API clients` | The calling client is itself a third-party (child) client        |
| 403    | `Child clients cannot create API clients` | The calling client is itself a third-party (child) client        |
| 404    | `API client not found`                    | No client with that ID owned by the authenticated user           |
| 409    | `client_id_url already registered`        | Another client already uses that `clientIdUrl`                   |

## Operational notes

Each third-party client gets its own rate limit bucket using the instance's default capacity and refill rate (`DEFAULT_RATE_LIMIT_CAPACITY` / `DEFAULT_RATE_LIMIT_REFILL_RATE`). Deactivating or deleting a parent via the [admin API](../admin/api-clients.md) cascades to all its children.

The admin API clients list (`GET /admin/api-clients`) returns `parent_client_id` and `owner_did` fields for each client and supports `?parent_id=` filtering. The dashboard's API Clients table shows these as "Parent Client" and "Owner" columns.
