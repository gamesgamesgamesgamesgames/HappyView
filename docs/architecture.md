# Architecture

Guide for contributors working on HappyView itself.

## Module overview

```
src/
  main.rs           Startup: config, DB, migrations, spawn workers, start server
  lib.rs            AppState struct, module declarations
  config.rs         Environment variable loading
  error.rs          AppError enum (Auth, BadRequest, Forbidden, Internal, NotFound, PdsError)
  server.rs         Axum router: fixed routes + admin nest + XRPC catch-all
  lexicon.rs        ParsedLexicon, LexiconRegistry (Arc<RwLock<HashMap>>)
  profile.rs        DID document resolution, PDS discovery, profile fetching
  jetstream.rs      Jetstream WebSocket listener, record indexing
  backfill.rs       Background worker for bulk record ingestion
  auth/
    middleware.rs   Claims extractor (validates Bearer token via AIP /oauth/userinfo)
  admin/
    mod.rs          Admin route definitions
    auth.rs         AdminAuth extractor (Claims + DID lookup + auto-bootstrap)
    admins.rs       Admin CRUD handlers
    lexicons.rs     Lexicon CRUD handlers
    stats.rs        Record count stats
    backfill.rs     Backfill job creation and status
    types.rs        Request/response structs for admin endpoints
  repo/
    mod.rs          Re-exports
    dpop.rs         DPoP JWT proof generation (ES256/P-256)
    pds.rs          PDS proxy helpers (JSON POST, blob POST, response forwarding)
    session.rs      ATP session fetching from AIP
    upload_blob.rs  Blob upload handler
    media.rs        Media blob URL enrichment
    at_uri.rs       AT URI parsing
  xrpc/
    mod.rs          Re-exports
    query.rs        Dynamic GET handler (single record + list with pagination)
    procedure.rs    Dynamic POST handler (create vs put auto-detection)
```

## Request flow

### Reads (queries)

```
Client GET /xrpc/{method}?params
  -> xrpc::xrpc_get()
  -> LexiconRegistry lookup (must be Query type)
  -> SQL query on records table (collection from target_collection)
  -> Media blob URL enrichment
  -> JSON response
```

### Writes (procedures)

```
Client POST /xrpc/{method} + Bearer token
  -> Claims extractor validates token via AIP /oauth/userinfo
  -> xrpc::xrpc_post()
  -> LexiconRegistry lookup (must be Procedure type)
  -> Fetch ATP session from AIP /api/atprotocol/session
  -> Generate DPoP proof (ES256)
  -> Proxy to user's PDS (createRecord or putRecord)
  -> Upsert record locally
  -> Forward PDS response
```

### Admin endpoints

```
Client request + Bearer token
  -> AdminAuth extractor:
     1. Claims validation via AIP
     2. DID lookup in admins table (auto-bootstrap if empty)
     3. 403 if not admin
  -> Admin handler
  -> JSON response
```

## Data flow

### Real-time indexing

```
Jetstream WebSocket
  -> Filter by wantedCollections (from record-type lexicons)
  -> commit events:
     create/update -> UPSERT into records table
     delete        -> DELETE from records table
  -> Cursor tracked in AtomicI64 (rewinds 5s on reconnect)
```

### Backfill

```
backfill_jobs table (status = pending)
  -> Worker picks up job
  -> Relay listReposByCollection -> list of DIDs
  -> For each DID (8 concurrent):
     PLC directory -> PDS endpoint
     PDS listRecords -> UPSERT into records table
  -> Update job status and counters
```

## Database schema

### `records`

| Column | Type | Description |
|--------|------|-------------|
| `uri` | text (PK) | AT URI (`at://did/collection/rkey`) |
| `did` | text | Author DID |
| `collection` | text | Lexicon NSID |
| `rkey` | text | Record key |
| `record` | jsonb | Record value |
| `cid` | text | Content identifier |
| `indexed_at` | timestamptz | When HappyView indexed this record |

### `lexicons`

| Column | Type | Description |
|--------|------|-------------|
| `id` | text (PK) | Lexicon NSID |
| `revision` | integer | Incremented on upsert |
| `lexicon_json` | jsonb | Raw lexicon definition |
| `lexicon_type` | text | record, query, procedure, definitions |
| `backfill` | boolean | Whether to backfill on upload |
| `target_collection` | text | For queries/procedures: which record collection |
| `created_at` | timestamptz | |
| `updated_at` | timestamptz | |

### `admins`

| Column | Type | Description |
|--------|------|-------------|
| `id` | uuid (PK) | |
| `did` | text (unique) | Admin's ATProto DID |
| `created_at` | timestamptz | |
| `last_used_at` | timestamptz | Updated on each authenticated request |

### `backfill_jobs`

| Column | Type | Description |
|--------|------|-------------|
| `id` | uuid (PK) | |
| `collection` | text | Target collection (null = all) |
| `did` | text | Target DID (null = all) |
| `status` | text | pending, running, completed, failed |
| `total_repos` | integer | |
| `processed_repos` | integer | |
| `total_records` | integer | |
| `error` | text | Error message if failed |
| `started_at` | timestamptz | |
| `completed_at` | timestamptz | |
| `created_at` | timestamptz | |

## Testing

```sh
# Unit tests (no database needed)
cargo test --lib

# All tests including e2e (requires Postgres)
docker compose -f docker-compose.test.yml up -d
TEST_DATABASE_URL=postgres://happyview:happyview@localhost:5433/happyview_test cargo test
docker compose -f docker-compose.test.yml down
```

E2e tests use `wiremock` to mock external services (AIP, PLC directory, PDSes) and a real Postgres database for full integration coverage.
