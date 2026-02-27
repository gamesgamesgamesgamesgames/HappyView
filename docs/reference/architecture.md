# Architecture

Guide for contributors working on HappyView itself. For a user-facing overview, see the [Introduction](/README.md).

## System overview

```mermaid
graph LR
  Application

  Application -->|"GET /xrpc/{method}"| Query
  Application -->|"POST /xrpc/{method}"| Procedure

  subgraph HappyView
    Query["Query Handler<br/><small>Lua Script (Optional)</small>"]
    Procedure["Procedure Handler<br/><small>Lua Script (Optional)</small>"]
  end

  Procedure --> DB
  Query --> DB

  Procedure -->|proxy write| PDS["User PDS"]

  DB[("PostgreSQL<br/><small>records · lexicons</small>")]

  Tap["Tap<br/><small>WebSocket</small>"] -->|record events| DB
  Relay["Relay<br/><small>Firehose</small>"] --> Tap
```

Reads flow top-down through the query handler to Postgres. Writes flow through the procedure handler to the user's PDS, then HappyView indexes the record locally. All record data enters the system through Tap, which handles both real-time firehose events and historical backfill. HappyView syncs collection filters to Tap and discovers repos via the relay for backfill, but Tap performs all record fetching.

## Module overview

```
src/
  main.rs           Startup: config, DB, migrations, spawn Tap worker, start server
  lib.rs            AppState struct, module declarations
  config.rs         Environment variable loading
  error.rs          AppError enum (Auth, BadRequest, Forbidden, Internal, NotFound, PdsError)
  server.rs         Axum router: fixed routes + admin nest + XRPC catch-all + static files
  lexicon.rs        ParsedLexicon, LexiconRegistry (Arc<RwLock<HashMap>>)
  profile.rs        DID document resolution, PDS discovery, profile fetching
  tap.rs            Tap WebSocket listener, collection filter sync, backfill delegation
  aip.rs            AIP reverse proxy
  resolve.rs        NSID authority resolution (DNS TXT → DID → PDS)
  auth/
    mod.rs          Re-exports
    middleware.rs   Claims extractor (validates Bearer token via AIP /oauth/userinfo)
    jwks.rs         JWKS key fetching
  admin/
    mod.rs          Admin route definitions
    auth.rs         AdminAuth extractor (Claims + DID lookup + auto-bootstrap)
    admins.rs       Admin CRUD handlers
    lexicons.rs     Lexicon CRUD handlers
    network_lexicons.rs  Network lexicon tracking (add, list, remove)
    records.rs      Record listing handler
    stats.rs        Record count stats
    backfill.rs     Backfill job creation (relay discovery + Tap delegation)
    types.rs        Request/response structs for admin endpoints
  lua/
    mod.rs          Re-exports
    context.rs      Lua context globals (method, params, input, caller_did, collection)
    db_api.rs       Lua database API (db.query, db.get, db.count)
    execute.rs      Script execution and sandbox setup
    record.rs       Lua Record API (constructor, save, delete, load)
    sandbox.rs      Restricted Lua environment (removed modules, instruction limit)
    tid.rs          TID generation for Lua scripts
  repo/
    mod.rs          Re-exports
    dpop.rs         DPoP JWT proof generation (ES256/P-256)
    pds.rs          PDS proxy helpers (JSON POST, blob POST, response forwarding)
    session.rs      ATP session fetching from AIP
    upload_blob.rs  Blob upload handler
  xrpc/
    mod.rs          Re-exports
    query.rs        Dynamic GET handler (Lua script or default: single record + list)
    procedure.rs    Dynamic POST handler (Lua script or default: create vs put)
```

## Request flow

### Reads (queries)

```
Client GET /xrpc/{method}?params
  -> xrpc::xrpc_get()
  -> LexiconRegistry lookup (must be Query type)
  -> If Lua script attached: execute script (has access to db API)
  -> Else: default SQL query on records table (collection from target_collection)
  -> JSON response
```

### Writes (procedures)

```
Client POST /xrpc/{method} + Bearer token
  -> Claims extractor validates token via AIP /oauth/userinfo
  -> xrpc::xrpc_post()
  -> LexiconRegistry lookup (must be Procedure type)
  -> If Lua script attached: execute script (has access to Record API)
  -> Else: default create/update (auto-detect based on uri field)
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
Tap WebSocket connection (tap::spawn)
  -> Collection filters synced to Tap on startup and lexicon changes
  -> Record events:
     create/update -> UPSERT into records table
     delete        -> DELETE from records table
  -> Lexicon schema events (com.atproto.lexicon.schema):
     -> Update tracked network lexicons in DB and registry
  -> Reconnects automatically on errors or collection filter changes
```

### Backfill

```
POST /admin/backfill
  -> Create backfill_jobs record (status = running)
  -> Relay listReposByCollection -> list of DIDs
  -> Send DIDs to Tap in batches of 1000 (POST /repos/add)
  -> Mark job as completed
  -> Tap fetches records asynchronously and delivers via WebSocket
```

## Database schema

### `records`

| Column       | Type        | Description                         |
| ------------ | ----------- | ----------------------------------- |
| `uri`        | text (PK)   | AT URI (`at://did/collection/rkey`) |
| `did`        | text        | Author DID                          |
| `collection` | text        | Lexicon NSID                        |
| `rkey`       | text        | Record key                          |
| `record`     | jsonb       | Record value                        |
| `cid`        | text        | Content identifier                  |
| `indexed_at` | timestamptz | When HappyView indexed this record  |

### `lexicons`

| Column              | Type        | Description                                     |
| ------------------- | ----------- | ----------------------------------------------- |
| `id`                | text (PK)   | Lexicon NSID                                    |
| `revision`          | integer     | Incremented on upsert                           |
| `lexicon_json`      | jsonb       | Raw lexicon definition                          |
| `lexicon_type`      | text        | record, query, procedure, definitions           |
| `backfill`          | boolean     | Whether to backfill on upload                   |
| `target_collection` | text        | For queries/procedures: which record collection |
| `created_at`        | timestamptz |                                                 |
| `updated_at`        | timestamptz |                                                 |

### `admins`

| Column         | Type          | Description                           |
| -------------- | ------------- | ------------------------------------- |
| `id`           | uuid (PK)     |                                       |
| `did`          | text (unique) | Admin's AT Protocol DID                   |
| `created_at`   | timestamptz   |                                       |
| `last_used_at` | timestamptz   | Updated on each authenticated request |

### `backfill_jobs`

| Column            | Type        | Description                         |
| ----------------- | ----------- | ----------------------------------- |
| `id`              | uuid (PK)   |                                     |
| `collection`      | text        | Target collection (null = all)      |
| `did`             | text        | Target DID (null = all)             |
| `status`          | text        | pending, running, completed, failed |
| `total_repos`     | integer     |                                     |
| `processed_repos` | integer     |                                     |
| `total_records`   | integer     |                                     |
| `error`           | text        | Error message if failed             |
| `started_at`      | timestamptz |                                     |
| `completed_at`    | timestamptz |                                     |
| `created_at`      | timestamptz |                                     |

## Testing

```sh
# Unit tests (no database needed)
cargo test --lib

# All tests including end-to-end (requires Postgres)
docker compose -f docker-compose.test.yml up -d
TEST_DATABASE_URL=postgres://happyview:happyview@localhost:5433/happyview_test cargo test
docker compose -f docker-compose.test.yml down
```

End-to-end tests use `wiremock` to mock external services (AIP, PLC directory, PDSes) and a real Postgres database for full integration coverage.
