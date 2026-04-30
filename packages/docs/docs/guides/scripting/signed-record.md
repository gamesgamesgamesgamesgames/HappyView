# Procedure: Signed Record

Save a record with an attestation signature attached.

**Lexicon type:** procedure

```lua
function handle()
  local r = Record(collection, {
    text = input.text,
    createdAt = now(),
  })
  r:save()

  local sig = nil
  if atproto.sign then
    sig = atproto.sign({ text = input.text, createdAt = r.createdAt })
  end

  return { uri = r._uri, cid = r._cid, signature = sig }
end
```

## How it works

1. Create and save the record.
2. Sign the record fields with [`atproto.sign()`](../../reference/lua/atproto-api.md#atprotosign). The `nil` guard lets the script work without a signer configured.
3. Return the signature alongside the URI.

## Usage

```sh
curl -X POST http://127.0.0.1:3000/xrpc/xyz.example.createPost \
  -H "X-Client-Key: $CLIENT_KEY" \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{ "text": "Hello world" }'
```

```json
{
  "uri": "at://did:plc:abc/xyz.example.post/3abc123",
  "cid": "bafyrei...",
  "signature": {
    "$type": "your.app.attestation",
    "key": "did:web:happyview.example.com#attestation",
    "signature": { "$bytes": "..." }
  }
}
```

## Use case

Attestation signatures let clients verify that a record was processed by your HappyView instance — useful for contributions, moderation decisions, or cross-instance data where provenance matters. The signature covers both the record content and the author's DID, so it can't be replayed across users or tampered with.

See [Attestation Signing](../features/attestation-signing.md) for setup and configuration, or [Verify Signed Record](signed-record-verify.md) for the read-side counterpart.
