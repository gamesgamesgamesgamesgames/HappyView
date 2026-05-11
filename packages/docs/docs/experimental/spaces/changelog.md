# Changelog

## Latest

### New endpoints

- **`createRecord`:** create a record with an auto-generated TID rkey instead of requiring the caller to supply one
- **`applyWrites`:** batch multiple create, update, and delete operations in a single request

### Optimistic concurrency

- **`swapRecord`:** optional CID-based concurrency guard on `putRecord`, `deleteRecord`, and individual operations within `applyWrites`. Returns `409 Conflict` when the record's current CID doesn't match.
- **`swapCommit`:** optional revision-based concurrency guard on `applyWrites`. Asserts the space's current revision before applying any writes. Returns `409 Conflict` on mismatch.
- Spaces now track a `revision` field (TID) that advances on every write.

### Space DID separation

- Spaces now have their own `did` field, distinct from the `owner_did` of the space creator. For personal spaces these are the same DID; multi-party spaces will have their own DID.
- All URI construction and lookups use the space's DID. Ownership checks use `owner_did`.
- New database migration adds the `did` column to the `spaces` table.

### Two-step credential flow

- Replaced the single `getCredential` endpoint with a two-step flow:
  1. **`getMemberGrant`:** proves membership and returns an HMAC-SHA256 grant (5-minute TTL)
  2. **`getSpaceCredential`:** exchanges the grant for an ES256 space credential JWT (4-hour TTL)
- Removed the `refreshCredential` endpoint (just repeat the two-step flow)

### Bearer auth for space credentials

- Space credentials are now passed as standard `Authorization: Bearer <token>` instead of a custom `X-Space-Credential` header. HappyView distinguishes credentials from other Bearer tokens by checking the JWT `typ` header (`space_credential`), matching Dan's reference implementation.
- No DPoP auth or client key needed when authenticating via space credential.

### Endpoint naming

- Space CRUD endpoints renamed to verbNoun format: `space.create` → `space.createSpace`, `space.get` → `space.getSpace`, `space.list` → `space.listSpaces`, `space.update` → `space.updateSpace`, `space.delete` → `space.deleteSpace`.
- Invite endpoints moved out of the `invite.*` sub-namespace: `invite.create` → `space.createInvite`, `invite.redeem` → `space.redeemInvite`, `invite.revoke` → `space.revokeInvite`, `invite.list` → `space.listInvites`.
- Old endpoint names are still available as legacy aliases and will be removed in a future release.

### Bug fixes

- Fixed `WriteOp` serde deserialization. `swapRecord` fields in `update` and `delete` operations now correctly deserialize from camelCase JSON.
- Credential `iss` claim now uses the space's DID instead of the owner's DID.
- `SpaceUri` parsing updated to use `did` (space DID) instead of `owner_did`.

---

## v2.5.0

_Released 2026-05-05_

Initial release of Permissioned Spaces behind the `feature.spaces_enabled` experimental flag.

### Features

- Space CRUD: `create`, `get`, `list`, `update`, `delete`
- Record operations: `putRecord`, `getRecord`, `listRecords`, `deleteRecord`
- Membership management: `addMember`, `removeMember`, `listMembers`
- Invite system: `invite.create`, `invite.redeem`, `invite.revoke`, `invite.list`
- `ats://` URI scheme for addressing permissioned data
- Access model with `default_allow` / `default_deny` modes and app allowlists/denylists
- Space credentials for cross-service read access via `X-Space-Credential` header
- Delegation: adding a space as a member transitively grants access to its members
- Lua scripting context includes space metadata (`space.did`, `space.owner_did`, `space.type_nsid`, `space.skey`)
