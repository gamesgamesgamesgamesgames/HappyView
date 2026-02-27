# Query: Expanded Query with Profiles

List statuses and include the profile of each user who created one.

**Lexicon type:** query

```lua
function handle()
  local limit = tonumber(params.limit) or 20
  if limit > 100 then limit = 100 end

  local result = db.query({
    collection = "xyz.statusphere.status",
    did = params.did,
    limit = limit,
    offset = tonumber(params.cursor) or 0,
  })

  -- Collect unique DIDs from the statuses
  local seen = {}
  local profile_uris = {}
  for _, status in ipairs(result.records) do
    local did = string.match(status.uri, "at://([^/]+)/")
    if did and not seen[did] then
      seen[did] = true
      profile_uris[#profile_uris + 1] = "at://" .. did .. "/app.bsky.actor.profile/self"
    end
  end

  -- Load all profiles in parallel
  local profiles = {}
  if #profile_uris > 0 then
    local loaded = Record.load_all(profile_uris)
    for i, profile in ipairs(loaded) do
      if profile then
        profiles[#profiles + 1] = profile
      end
    end
  end

  return {
    statuses = result.records,
    profiles = profiles,
    cursor = result.cursor,
  }
end
```

## How it works

1. Query statuses from the target collection with pagination, same as a normal list query.
2. Extract the unique DIDs from the returned status URIs using `string.match`.
3. Build an AT URI for each DID's `app.bsky.actor.profile/self` record (this is where Bluesky profiles live).
4. Load all profiles in parallel with [`Record.load_all`](../../guides/scripting.md#static-methods). Profiles that aren't indexed locally return `nil` and are skipped.
5. Return statuses and profiles as separate keys, with the cursor from the status query.

## Usage

```
GET /xrpc/xyz.statusphere.listStatusesWithProfiles?limit=10
GET /xrpc/xyz.statusphere.listStatusesWithProfiles?did=did:plc:abc
GET /xrpc/xyz.statusphere.listStatusesWithProfiles?cursor=20&limit=20
```

```json
{
  "statuses": [
    { "uri": "at://did:plc:abc/xyz.statusphere.status/3abc123", "status": "😊", "createdAt": "..." },
    { "uri": "at://did:plc:def/xyz.statusphere.status/3def456", "status": "🌟", "createdAt": "..." }
  ],
  "profiles": [
    { "uri": "at://did:plc:abc/app.bsky.actor.profile/self", "displayName": "Alice", "avatar": "..." },
    { "uri": "at://did:plc:def/app.bsky.actor.profile/self", "displayName": "Bob", "avatar": "..." }
  ],
  "cursor": "10"
}
```

## Use case

This pattern avoids N+1 queries (fetching each author's profile individually) on the client side. Instead of fetching statuses and then making a separate request for each user's profile, the client gets everything in one call. The deduplication step ensures each profile is loaded only once even if multiple statuses are from the same user.

Note that `Record.load_all` reads from HappyView's local index. Profiles only appear if `app.bsky.actor.profile` is also being indexed. If a profile hasn't been indexed yet, it's silently omitted from the response.
