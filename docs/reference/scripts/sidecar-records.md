# Procedure: Create Sidecar Records

Create two records with different collection NSIDs but the same rkey, linking them together by key.

**Lexicon type:** procedure

```lua
function handle()
  local rkey = TID()

  local post = Record("xyz.statusphere.post", {
    text = input.text,
    createdAt = now(),
  })
  post:set_rkey(rkey)

  local metadata = Record("xyz.statusphere.postMetadata", {
    lang = input.lang or "en",
    source = input.source or "web",
    createdAt = now(),
  })
  metadata:set_rkey(rkey)

  Record.save_all({ post, metadata })

  return {
    post = { uri = post._uri, cid = post._cid },
    metadata = { uri = metadata._uri, cid = metadata._cid },
  }
end
```

## How it works

1. Generate a single [`TID()`](../../guides/scripting#utility-globals) to use as the rkey for both records.
2. Create a `Record` for each collection and call `r:set_rkey()` with the shared rkey.
3. Save both records in parallel with [`Record.save_all()`](../../guides/scripting#static-methods).
4. Return both URIs so the client knows the identity of each record.

## Usage

```sh
curl -X POST http://localhost:3000/xrpc/xyz.statusphere.createPost \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{ "text": "Hello world", "lang": "en", "source": "web" }'
```

The response includes URIs for both the post and its metadata:

```json
{
  "post": {
    "uri": "at://did:plc:abc/xyz.statusphere.post/3abc123",
    "cid": "bafyrei..."
  },
  "metadata": {
    "uri": "at://did:plc:abc/xyz.statusphere.postMetadata/3abc123",
    "cid": "bafyrei..."
  }
}
```

## Use case

Sidecar records are useful when you want to associate related data across collections without embedding everything in a single record. Because they share an rkey, you can derive one URI from the other:

```
at:// did:plc:abc /xyz.statusphere.post         /3abc123
at:// did:plc:abc /xyz.statusphere.postMetadata /3abc123
                                                 ^^^^^^^ same rkey
```

This is a common AT Protocol pattern for keeping a primary record lean while storing auxiliary data (metadata, reactions, settings) in a companion collection.
