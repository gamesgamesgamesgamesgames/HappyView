# OAuth API: Self-Service API Clients

Third-party applications can create child API clients on behalf of authenticated users via `POST /oauth/api-clients`. A child client is always tied to exactly one parent — the admin-created top-level API client that made the request. Only one level of nesting is allowed; child clients cannot create further children. Each child client gets its own rate limit bucket with instance default settings.

The endpoint uses [DPoP authentication](../../getting-started/authentication.md#authenticating-users-for-procedures). See the [admin API client docs](../admin/api-clients.md) for managing clients through the admin API, and the [API Clients guide](../../guides/features/api-clients.md) for an overview of how API clients work in HappyView.

## Create a child client

```
POST /oauth/api-clients
```

Requires three headers:

| Header          | Value                                                        |
| --------------- | ------------------------------------------------------------ |
| `Authorization` | `DPoP <access_token>`                                        |
| `DPoP`          | A DPoP proof JWT (method: `POST`, htu: the full request URL) |
| `X-Client-Key`  | The parent client's `client_key`                             |

The access token must belong to a valid DPoP session for the parent client. The parent client's owner (its `created_by` DID) must exist in the HappyView `users` table.

```sh
curl -X POST https://happyview.example.com/oauth/api-clients \
  -H "X-Client-Key: hvc_parent_key" \
  -H "Authorization: DPoP eyJhbG..." \
  -H "DPoP: eyJhbG..." \
  -H "Content-Type: application/json" \
  -d '{
    "name": "My Child App",
    "client_id_url": "https://child.example.com/client-metadata.json",
    "client_uri": "https://child.example.com",
    "redirect_uris": ["https://child.example.com/callback"],
    "client_type": "confidential"
  }'
```

| Field             | Type     | Required | Description                                      |
| ----------------- | -------- | -------- | ------------------------------------------------ |
| `name`            | string   | yes      | Display name for the child client                |
| `client_id_url`   | string   | yes      | Unique OAuth client ID URL                       |
| `client_uri`      | string   | yes      | The client's homepage URL                        |
| `redirect_uris`   | string[] | yes      | OAuth redirect URIs                              |
| `scopes`          | string   | no       | Space-separated OAuth scopes (default `"atproto"`) |
| `client_type`     | string   | no       | `"confidential"` or `"public"` (default `"confidential"`) |
| `allowed_origins` | string[] | no       | CORS allowed origins                             |

**Response**: `201 Created`

```json
{
  "id": "550e8400-e29b-41d4-a716-446655440000",
  "client_key": "hvc_a1b2c3d4e5f6...",
  "client_secret": "hvs_f6e5d4c3b2a1...",
  "name": "My Child App",
  "client_id_url": "https://child.example.com/client-metadata.json",
  "client_type": "confidential"
}
```

The `client_secret` is only present for confidential clients and is only returned in this response — store it securely. It is stored as a SHA-256 hash and cannot be retrieved again.

## Errors

| Status | Error                                    | Cause                                                              |
| ------ | ---------------------------------------- | ------------------------------------------------------------------ |
| 400    | `Invalid client_type`                    | `client_type` is not `"confidential"` or `"public"`                |
| 400    | `invalid request body`                   | Missing required fields or malformed JSON                          |
| 401    | `Missing client identification`          | `X-Client-Key` header is absent                                    |
| 401    | `DPoP authorization scheme required`     | `Authorization` header doesn't start with `DPoP `                  |
| 401    | `DPoP proof header required`             | `DPoP` header is absent                                            |
| 401    | `token_expired`                          | The access token has expired                                       |
| 401    | `Invalid client`                         | `X-Client-Key` doesn't match a known client                       |
| 403    | `Child clients cannot create API clients` | The calling client is itself a child                               |
| 403    | `Parent client owner not found`          | The parent client's `created_by` DID is not in the `users` table   |
| 409    | `client_id_url already registered`       | Another client already uses that `client_id_url`                   |

## Operational notes

Each child client gets its own rate limit bucket using the instance's default capacity and refill rate (`DEFAULT_RATE_LIMIT_CAPACITY` / `DEFAULT_RATE_LIMIT_REFILL_RATE`). Deactivating or deleting a parent via the [admin API](../admin/api-clients.md) cascades to all its children.

The admin API clients list (`GET /admin/api-clients`) returns `parent_client_id` and `owner_did` fields for each client and supports `?parent_id=` filtering. The dashboard's API Clients table shows these as "Parent Client" and "Owner" columns.
