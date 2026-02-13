# Backfill

Backfill bulk-indexes existing records from the ATProto network into HappyView's database. It discovers repos via the relay and fetches records directly from each user's PDS.

## When backfill runs

- **Automatically** when a record-type lexicon is uploaded with `backfill: true` (the default)
- **Manually** via `POST /admin/backfill`

## How it works

1. **Determine target collections**: uses the specified collection, or all record lexicons with `backfill: true`
2. **Discover DIDs**: calls the relay's `com.atproto.sync.listReposByCollection` to find repos that contain records for each collection (paginated, 1000 per page)
3. **Fetch records**: for each DID, resolves the PDS endpoint via PLC directory, then calls `com.atproto.repo.listRecords` on the PDS (paginated, 100 per page)
4. **Upsert**: inserts or updates records in Postgres

## Creating a backfill job

### Backfill all collections

```sh
curl -X POST http://localhost:3000/admin/backfill \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{}'
```

### Backfill a specific collection

```sh
curl -X POST http://localhost:3000/admin/backfill \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{ "collection": "games.gamesgamesgamesgames.game" }'
```

### Backfill a specific DID

```sh
curl -X POST http://localhost:3000/admin/backfill \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "collection": "games.gamesgamesgamesgames.game",
    "did": "did:plc:abc123"
  }'
```

## Monitoring progress

```sh
curl http://localhost:3000/admin/backfill/status \
  -H "Authorization: Bearer $TOKEN"
```

```json
[
  {
    "id": "550e8400-e29b-41d4-a716-446655440000",
    "collection": "games.gamesgamesgamesgames.game",
    "did": null,
    "status": "running",
    "total_repos": 42,
    "processed_repos": 15,
    "total_records": 350,
    "error": null,
    "started_at": "2025-01-01T00:01:00Z",
    "completed_at": null,
    "created_at": "2025-01-01T00:00:00Z"
  }
]
```

Job statuses: `pending` -> `running` -> `completed` or `failed`.

## Concurrency

The backfill worker processes one job at a time, polling for pending jobs every 5 seconds. Within a job, up to 8 PDSes are fetched concurrently.
