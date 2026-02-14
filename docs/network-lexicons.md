# Network Lexicons

Network lexicons are lexicon definitions that HappyView fetches directly from the ATProto network rather than being uploaded manually via the admin API. An admin specifies an NSID, HappyView resolves the authority's repo, fetches the lexicon record, and keeps it updated via Jetstream.

## How it works

### NSID authority resolution

Lexicon records live in repos as `com.atproto.lexicon.schema` with the rkey set to the NSID. To find which repo holds a lexicon, HappyView resolves the NSID's authority:

1. Extract the authority from the NSID (all segments except the last). For example, `games.gamesgamesgamesgames.game` has authority `games.gamesgamesgamesgames`.
2. Reverse the authority segments to form a domain: `gamesgamesgamesgames.games`.
3. Look up the DNS TXT record at `_lexicon.{domain}` (e.g. `_lexicon.gamesgamesgamesgames.games`).
4. Parse the TXT record for a `did=<DID>` value.
5. Resolve the DID to a PDS endpoint via the PLC directory.

Resolution is **non-hierarchical** --- each authority requires its own explicit TXT record.

### Fetching

Once the authority DID and PDS endpoint are known, HappyView calls `com.atproto.repo.getRecord` with:
- `repo` = the authority DID
- `collection` = `com.atproto.lexicon.schema`
- `rkey` = the NSID

The `value` field of the response is the raw lexicon JSON.

### Live updates via Jetstream

Jetstream always subscribes to `com.atproto.lexicon.schema` alongside the dynamic record collections. When a commit event arrives:

- **create/update**: If the event's DID and rkey match a tracked network lexicon (`authority_did` and `nsid`), the lexicon is parsed, upserted into the `lexicons` table and in-memory registry, and Jetstream is notified if it's a record type.
- **delete**: The lexicon is removed from the `lexicons` table and registry.

### Startup re-fetch

On every startup, HappyView re-fetches all network lexicons from their respective PDSes. This ensures consistency even if Jetstream events were missed while offline. Failures are logged as warnings but don't block startup.

## Admin API

See [Admin API - Network Lexicons](admin-api.md#network-lexicons) for endpoint details.

### Quick reference

```sh
# Add a network lexicon
curl -X POST http://localhost:3000/admin/network-lexicons \
  -H "$AUTH" -H "Content-Type: application/json" \
  -d '{ "nsid": "games.gamesgamesgamesgames.game" }'

# List tracked network lexicons
curl http://localhost:3000/admin/network-lexicons -H "$AUTH"

# Remove a network lexicon
curl -X DELETE http://localhost:3000/admin/network-lexicons/games.gamesgamesgamesgames.game \
  -H "$AUTH"
```
