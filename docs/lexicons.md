# Lexicons

Lexicons are ATProto schema definitions that tell HappyView which records to index and what XRPC endpoints to serve. HappyView supports uploading lexicons at runtime via the admin API.

## Supported lexicon types

| Type | Effect |
|------|--------|
| `record` | Subscribes to Jetstream for that collection and indexes records into Postgres |
| `query` | Registers a `GET /xrpc/{nsid}` endpoint that queries indexed records |
| `procedure` | Registers a `POST /xrpc/{nsid}` endpoint that proxies writes to the user's PDS |
| `definitions` | Stored but does not generate routes or subscriptions |

## Uploading a lexicon

```sh
curl -X POST http://localhost:3000/admin/lexicons \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "lexicon_json": {
      "lexicon": 1,
      "id": "games.gamesgamesgamesgames.game",
      "defs": {
        "main": {
          "type": "record",
          "key": "tid",
          "record": {
            "type": "object",
            "properties": {
              "title": { "type": "string" }
            }
          }
        }
      }
    },
    "backfill": true
  }'
```

Re-uploading the same lexicon ID increments its revision number.

## The `target_collection` field

Query and procedure lexicons need to know which record collection they operate on. Set `target_collection` to the NSID of the record lexicon:

```sh
curl -X POST http://localhost:3000/admin/lexicons \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "lexicon_json": {
      "lexicon": 1,
      "id": "games.gamesgamesgamesgames.listGames",
      "defs": {
        "main": {
          "type": "query",
          "parameters": {
            "type": "params",
            "properties": {
              "limit": { "type": "integer" }
            }
          },
          "output": { "encoding": "application/json" }
        }
      }
    },
    "target_collection": "games.gamesgamesgamesgames.game"
  }'
```

Without `target_collection`, queries and procedures won't know which DB records to read from.

## The `backfill` flag

When `backfill` is `true` (the default), uploading a record-type lexicon triggers a backfill job that discovers existing repos via the relay and fetches historical records from their PDSes.

Set `backfill: false` if you only want to index new records going forward.

## Jetstream collection filters

When record-type lexicons change (uploaded or deleted), HappyView automatically reconnects to Jetstream with an updated collection filter. If no record lexicons exist, the Jetstream listener idles without connecting.

## Example: full setup

Upload the record lexicon, then a query and a procedure that target it:

```sh
# 1. Record lexicon (triggers Jetstream subscription + backfill)
curl -X POST http://localhost:3000/admin/lexicons \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "lexicon_json": { "lexicon": 1, "id": "games.gamesgamesgamesgames.game", "defs": { "main": { "type": "record", "key": "tid", "record": { "type": "object", "properties": { "title": { "type": "string" } } } } } },
    "backfill": true
  }'

# 2. Query lexicon
curl -X POST http://localhost:3000/admin/lexicons \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "lexicon_json": { "lexicon": 1, "id": "games.gamesgamesgamesgames.listGames", "defs": { "main": { "type": "query", "output": { "encoding": "application/json" } } } },
    "target_collection": "games.gamesgamesgamesgames.game"
  }'

# 3. Procedure lexicon
curl -X POST http://localhost:3000/admin/lexicons \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "lexicon_json": { "lexicon": 1, "id": "games.gamesgamesgamesgames.createGame", "defs": { "main": { "type": "procedure", "input": { "encoding": "application/json" }, "output": { "encoding": "application/json" } } } },
    "target_collection": "games.gamesgamesgamesgames.game"
  }'
```
