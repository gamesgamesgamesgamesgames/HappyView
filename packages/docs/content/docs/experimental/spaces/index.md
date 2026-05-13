---
title: "Overview"
---

<Callout type="error" title="Experimental">
Permissioned Spaces are experimental and the API will change. This implementation follows Daniel Holmgren's [Permissioned Data Diaries](https://dholms.leaflet.pub/3meluqcwky22a) and aligns structurally with the `permissioned-data` branch on `bluesky-social/atproto`, but uses a `dev.happyview` namespace to allow iteration while the official spec stabilizes.
</Callout>

Spaces are containers for permissioned data in atproto. Unlike regular public records that live in a user's repo, space records are gated by membership — only members can read or write data within a space.

## Concepts

A **space** is identified by three components:

- **Space DID** — the space's own decentralized identifier (for personal spaces, this is the user's DID)
- **Type** — the space type as an NSID, describing the modality (e.g. a forum, a group chat, a photo album)
- **Space key (skey)** — a short string differentiating multiple spaces of the same type

These form the space URI: `ats://<space-did>/<type>/<skey>`

A **space record** adds three more components to the URI: the author's DID, the collection NSID, and the record key:

```
ats://<space-did>/<type-nsid>/<skey>/<author-did>/<collection>/<rkey>
```

## Feature flag

In HappyView, spaces are gated behind the `feature.spaces_enabled` instance setting. Enable it in the dashboard under **Settings** or via the admin API:

```sh
curl -X PUT http://127.0.0.1:3000/admin/settings/feature.spaces_enabled \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"value": "true"}'
```

When disabled, all `/xrpc/dev.happyview.space.*` endpoints return `501 Not Implemented`.

## Endpoints

All space endpoints live under the `dev.happyview.space` namespace and require [DPoP authentication](../../getting-started/authentication.md).

| Endpoint                                 | Method | Description                           |
| ---------------------------------------- | ------ | ------------------------------------- |
| `dev.happyview.space.createSpace`        | POST   | Create a space                        |
| `dev.happyview.space.getSpace`           | GET    | Get a space by URI                    |
| `dev.happyview.space.listSpaces`         | GET    | List spaces by membership             |
| `dev.happyview.space.updateSpace`        | POST   | Update space metadata                 |
| `dev.happyview.space.deleteSpace`        | POST   | Delete a space                        |
| `dev.happyview.space.createRecord`       | POST   | Create a record (auto-generated rkey) |
| `dev.happyview.space.putRecord`          | POST   | Write a record                        |
| `dev.happyview.space.getRecord`          | GET    | Get a record                          |
| `dev.happyview.space.listRecords`        | GET    | List records                          |
| `dev.happyview.space.deleteRecord`       | POST   | Delete a record                       |
| `dev.happyview.space.applyWrites`        | POST   | Batch write operations                |
| `dev.happyview.space.addMember`          | POST   | Add a member                          |
| `dev.happyview.space.removeMember`       | POST   | Remove a member                       |
| `dev.happyview.space.listMembers`        | GET    | List resolved members                 |
| `dev.happyview.space.createInvite`       | POST   | Create an invite                      |
| `dev.happyview.space.redeemInvite`       | POST   | Redeem an invite                      |
| `dev.happyview.space.revokeInvite`       | POST   | Revoke an invite                      |
| `dev.happyview.space.listInvites`        | GET    | List invites                          |
| `dev.happyview.space.getMemberGrant`     | POST   | Prove membership (step 1)             |
| `dev.happyview.space.getSpaceCredential` | POST   | Get a space credential (step 2)       |

## Access model

Spaces have an **access mode** that controls third-party app access:

- **`default_allow`** — any app can access (with optional denylist)
- **`default_deny`** — only explicitly allowed apps can access

Individual users access spaces through **membership**. Members have either `read` or `write` access. Write access implies read. The space creator is automatically added as a write member.

Spaces also support **delegation** — adding another space as a member, which transitively grants access to all members of the delegated space.

## Divergences from the reference spec

HappyView mostly mirrors [Daniel Holmgren's `permissioned-data` branch](https://github.com/bluesky-social/atproto/tree/permissioned-data) but diverges in some areas. These will narrow as the official spec stabilizes.

### HappyView extensions (not in the reference branch)

- **`isDelegation` on members** allows spaces to be members of other spaces
- **`displayName`, `description`, `accessMode` on spaces** — the reference space model is minimal (`uri`, `isOwner`, `isMember`, `createdAt`)
- **`appAllowlist` / `appDenylist` / `managingAppDid`** — app-level access control layer
- **`config` object** on spaces (e.g. `membershipPublic`, `recordsPublic`)
- **Invite system** — `createInvite`, `redeemInvite`, `revokeInvite`, `listInvites`
- **`read` / `write` access levels** — the reference branch treats membership as binary

### Reference features not yet implemented

- **Oplogs** — `getRepoOplog`, `getMemberOplog`, `getRepoState`, `getMemberState` (sync primitives for space data)
- **Push notifications** — `notifyWrite`, `notifyMembership` (service-to-service event delivery)
- **Space-scoped blobs** — `uploadBlob` for blobs within a space context
- **Owner record deletion** — in the reference branch the space owner can delete any record; HappyView restricts `deleteRecord` to the record's author only

## Next steps

- [Managing Spaces](./managing-spaces.md) — create, update, and delete spaces
- [Members](./members.md) — manage membership and delegation
- [Records](./records.md) — read and write permissioned data
- [Credentials](./credentials.md) — cross-service authentication for spaces
- [Invites](./invites.md) — invite-based membership
