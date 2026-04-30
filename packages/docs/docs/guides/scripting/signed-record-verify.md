# Query: Verify Signed Record

Fetch a record and verify its attestation signature.

**Lexicon type:** query

```lua
function handle()
  local record = db.get(params.uri)
  if not record then
    return { error = "not found" }
  end

  local verified = false
  if atproto.verify_signature and record.signature then
    verified = atproto.verify_signature(
      { text = record.text, createdAt = record.createdAt },
      record.signature,
      params.did
    )
  end

  return { record = record, verified = verified }
end
```

## How it works

1. Fetch the record by AT URI.
2. If a signature is present, rebuild the same field table that was signed and verify it with [`atproto.verify_signature()`](../../reference/lua/atproto-api.md#atprotoverify_signature).
3. Return `verified = true` if the signature is valid, `false` if it's missing, invalid, or the signer isn't configured.

## Usage

```sh
curl "http://127.0.0.1:3000/xrpc/xyz.example.getPost?uri=at://did:plc:abc/xyz.example.post/3abc123&did=did:plc:abc"
```

```json
{
  "record": {
    "uri": "at://did:plc:abc/xyz.example.post/3abc123",
    "text": "Hello world",
    "createdAt": "2026-04-30T12:00:00Z"
  },
  "verified": true
}
```

## Use case

Pair this with the [Signed Record](signed-record.md) procedure to create a write-then-verify flow. The query re-derives the CID from the same fields that were originally signed, so any tampering between write and read is caught.

See [Attestation Signing](../features/attestation-signing.md) for setup and configuration.
