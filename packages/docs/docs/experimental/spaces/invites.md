# Invites

:::caution Experimental
This API is experimental and will change. See the [Permissioned Spaces overview](../spaces.md) for context.
:::

Invites let space owners distribute membership tokens without knowing recipients' DIDs in advance.

:::info HappyView Extension
Invites are a HappyView-specific feature, not part of the AT Protocol spaces spec. They may be replaced by a different mechanism in the future.
:::

## Creating an invite

Only the space owner or a super admin can create invites.

```sh
curl -X POST 'https://happyview.example.com/xrpc/dev.happyview.space.createInvite' \
  -H 'X-Client-Key: hvc_...' \
  -H 'Authorization: DPoP <token>' \
  -H 'DPoP: <proof>' \
  -H 'Content-Type: application/json' \
  -d '{
    "space": "ats://did:plc:abc123/com.example.forum/main",
    "access": "write",
    "maxUses": 10,
    "expiresAt": "2026-06-01T00:00:00Z"
  }'
```

**Input:**

| Field | Type | Required | Default | Description |
|---|---|---|---|---|
| `space` | string | Yes | | The space this invite is for |
| `access` | string | No | `read` | Access level granted on redemption (`read` or `write`) |
| `maxUses` | integer | No | unlimited | Maximum number of times the invite can be redeemed |
| `expiresAt` | string (datetime) | No | never | When the invite expires |

**Response (201):**

```json
{
  "inviteId": "uuid",
  "token": "a1b2c3d4e5f6...",
  "access": "write",
  "maxUses": 10,
  "expiresAt": "2026-06-01T00:00:00Z"
}
```

:::warning
The `token` is only returned once. It is stored as a SHA-256 hash — HappyView cannot recover the plaintext.
:::

## Redeeming an invite

Any authenticated user can redeem an invite token to join the space.

```sh
curl -X POST 'https://happyview.example.com/xrpc/dev.happyview.space.redeemInvite' \
  -H 'X-Client-Key: hvc_...' \
  -H 'Authorization: DPoP <token>' \
  -H 'DPoP: <proof>' \
  -H 'Content-Type: application/json' \
  -d '{
    "token": "a1b2c3d4e5f6..."
  }'
```

**Response (201):**

```json
{
  "uri": "ats://did:plc:abc123/com.example.forum/main",
  "access": "write"
}
```

Redemption fails if:

- The token is invalid (no matching hash found)
- The invite has been revoked
- The invite has reached its `maxUses`
- The invite has expired
- The user is already a member of the space

## Revoking an invite

```sh
curl -X POST 'https://happyview.example.com/xrpc/dev.happyview.space.revokeInvite' \
  -H 'X-Client-Key: hvc_...' \
  -H 'Authorization: DPoP <token>' \
  -H 'DPoP: <proof>' \
  -H 'Content-Type: application/json' \
  -d '{
    "space": "ats://did:plc:abc123/com.example.forum/main",
    "inviteId": "uuid"
  }'
```

Revoking an invite prevents future redemptions but does not remove members who already redeemed it.

## Listing invites

Only the space owner or a super admin can list invites.

```sh
curl 'https://happyview.example.com/xrpc/dev.happyview.space.listInvites?space=ats://did:plc:abc123/com.example.forum/main' \
  -H 'X-Client-Key: hvc_...' \
  -H 'Authorization: DPoP <token>' \
  -H 'DPoP: <proof>'
```

**Response:**

```json
{
  "invites": [
    {
      "id": "uuid",
      "access": "write",
      "maxUses": 10,
      "uses": 3,
      "expiresAt": "2026-06-01T00:00:00Z",
      "revoked": false,
      "createdBy": "did:plc:abc123",
      "createdAt": "2026-05-09T12:00:00Z"
    }
  ]
}
```

The token itself is never returned in list responses — only the invite metadata.
