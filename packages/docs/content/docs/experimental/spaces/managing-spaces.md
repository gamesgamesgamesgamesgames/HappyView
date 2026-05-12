---
title: "Managing Spaces"
---

<Callout type="error" title="Experimental">
This API is experimental and will change. See the [Permissioned Spaces overview](../spaces.md) for context.
</Callout>

## Creating a space

```sh
curl -X POST 'https://happyview.example.com/xrpc/dev.happyview.space.createSpace' \
  -H 'X-Client-Key: hvc_...' \
  -H 'Authorization: DPoP <token>' \
  -H 'DPoP: <proof>' \
  -H 'Content-Type: application/json' \
  -d '{
    "type": "com.example.forum",
    "skey": "main",
    "displayName": "My Forum",
    "description": "A place for discussion",
    "accessMode": "default_allow"
  }'
```

**Input:**

| Field            | Type          | Required | Description                                       |
| ---------------- | ------------- | -------- | ------------------------------------------------- |
| `type`           | string (NSID) | Yes      | The space type; describes what this space is for  |
| `skey`           | string        | Yes      | Space key; differentiates spaces of the same type |
| `displayName`    | string        | No       | Human-readable name                               |
| `description`    | string        | No       | Description of the space                          |
| `accessMode`     | string        | No       | `default_allow` (default) or `default_deny`       |
| `managingAppDid` | string        | No       | DID of the application that manages this space    |
| `config`         | object        | No       | Space configuration (see below)                   |

**Response (201):**

```json
{
  "uri": "ats://did:plc:abc123/com.example.forum/main"
}
```

The creator is automatically added as a write member. Use [`dev.happyview.space.getSpace`](#getting-a-space) to retrieve the full space object.

### Space configuration

The `config` object supports:

| Field              | Type    | Default | Description                                               |
| ------------------ | ------- | ------- | --------------------------------------------------------- |
| `membershipPublic` | boolean | `false` | Whether the member list is visible without authentication |
| `recordsPublic`    | boolean | `false` | Whether records are readable without membership           |

Additional fields are preserved as-is.

## Getting a space

```sh
curl 'https://happyview.example.com/xrpc/dev.happyview.space.getSpace?space=ats://did:plc:abc123/com.example.forum/main' \
  -H 'X-Client-Key: hvc_...' \
  -H 'Authorization: DPoP <token>' \
  -H 'DPoP: <proof>'
```

If `membershipPublic` is `false`, the caller must be authenticated and be a member (or the owner) to see the space. Non-members receive a `404 Not Found`.

## Listing spaces

Returns spaces where the authenticated user is a member.

```sh
curl 'https://happyview.example.com/xrpc/dev.happyview.space.listSpaces?limit=20' \
  -H 'X-Client-Key: hvc_...' \
  -H 'Authorization: DPoP <token>' \
  -H 'DPoP: <proof>'
```

**Parameters:**

| Field    | Type    | Required | Default | Description                  |
| -------- | ------- | -------- | ------- | ---------------------------- |
| `limit`  | integer | No       | 50      | Max spaces to return (1-100) |
| `cursor` | string  | No       |         | Pagination cursor            |

**Response:**

```json
{
  "spaces": [
    {
      "uri": "ats://did:plc:abc123/com.example.forum/main",
      "isOwner": true
    }
  ],
  "cursor": "MjAyNi0wNS0wOVQxMjowMDowMFp8YXRzOi8vZGlkOnBsYzphYmMxMjMvY29tLmV4YW1wbGUuZm9ydW0vbWFpbg"
}
```

## Updating a space

Only the space owner or a HappView super admin can update a space.

```sh
curl -X POST 'https://happyview.example.com/xrpc/dev.happyview.space.updateSpace' \
  -H 'X-Client-Key: hvc_...' \
  -H 'Authorization: DPoP <token>' \
  -H 'DPoP: <proof>' \
  -H 'Content-Type: application/json' \
  -d '{
    "space": "ats://did:plc:abc123/com.example.forum/main",
    "displayName": "Updated Forum Name",
    "accessMode": "default_deny",
    "appAllowlist": ["did:web:myapp.example.com"]
  }'
```

All fields except `space` are optional. Only provided fields are updated. To clear an optional field, pass `null`.

## Deleting a space

Only the space owner or a HappyView super admin can delete a space.

```sh
curl -X POST 'https://happyview.example.com/xrpc/dev.happyview.space.deleteSpace' \
  -H 'X-Client-Key: hvc_...' \
  -H 'Authorization: DPoP <token>' \
  -H 'DPoP: <proof>' \
  -H 'Content-Type: application/json' \
  -d '{"space": "ats://did:plc:abc123/com.example.forum/main"}'
```

<Callout type="warn">
Deleting a space does not currently cascade to records, members, or credentials. This behavior may change.
</Callout>
