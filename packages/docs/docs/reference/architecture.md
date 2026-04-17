# Architecture

Guide for contributors working on HappyView itself. For a user-facing overview, see the [Introduction](../README.md).

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

  DB[("SQLite / PostgreSQL<br/><small>records · lexicons</small>")]

  Jetstream["Jetstream<br/><small>WebSocket</small>"] -->|record events| DB
  Relay["Relay<br/><small>listReposByCollection</small>"] -->|repo discovery| Backfill
  Backfill["Backfill Worker"] -->|listRecords| PDS
  Backfill --> DB
```

Reads flow top-down through the query handler to the database (SQLite by default, or Postgres). Writes flow through the procedure handler to the user's PDS, then HappyView indexes the record locally. Real-time record events stream in via [Jetstream](https://github.com/bluesky-social/jetstream); historical records are backfilled in-process by discovering repos via the relay's `listReposByCollection` and fetching records directly from each PDS.

## Module overview

```
src/
  main.rs           Startup: config, DB, migrations, build OAuth client, spawn Jetstream worker, start server
  lib.rs            AppState struct (incl. OAuth client + cookie key), module declarations
  config.rs         Environment variable loading
  dns.rs            DNS TXT resolver for atrium handle resolution
  error.rs          AppError enum (Auth, BadRequest, Forbidden, Internal, NotFound, PdsError)
  server.rs         Axum router: fixed routes + admin nest + auth routes + XRPC catch-all + static files
  lexicon.rs        ParsedLexicon, LexiconRegistry (Arc<RwLock<HashMap>>)
  profile.rs        DID document resolution, PDS discovery, profile fetching
  jetstream.rs      Jetstream WebSocket listener, collection filter sync, cursor persistence
  resolve.rs        NSID authority resolution (DNS TXT → DID → PDS)
  auth/
    mod.rs          Re-exports, COOKIE_NAME constant
    middleware.rs   Claims extractor (cookie auth, API key, or service auth JWT)
    routes.rs       OAuth endpoints (/auth/login, /auth/callback, /auth/logout, /auth/me)
    oauth_store.rs  Database-backed session and state stores for atrium-oauth
    service_auth.rs XRPC service-to-service JWT validation (ES256/ES256K)
  admin/
    mod.rs          Admin route definitions
    auth.rs         UserAuth extractor (Claims + DID lookup + permission check + auto-bootstrap)
    users.rs        User CRUD handlers (create, list, get, delete, update permissions, transfer super)
    permissions.rs  Permission enum (20 permissions), templates (Viewer, Operator, Manager, FullAccess)
    api_keys.rs     API key CRUD handlers (create, list, revoke) with scoped permissions
    events.rs       Event log query handler
    settings.rs     Instance settings CRUD handlers (list, upsert, delete, logo upload/serve)
    script_variables.rs  Script variable CRUD handlers (list, upsert, delete)
    lexicons.rs     Lexicon CRUD handlers
    network_lexicons.rs  Network lexicon tracking (add, list, remove)
    records.rs      Record listing handler
    stats.rs        Record count stats
    backfill.rs     Backfill job runner (relay discovery + per-PDS listRecords)
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
    pds.rs          PDS proxy helpers (JSON POST, blob POST, response forwarding via OAuth session)
    session.rs      OAuth session restoration from atrium store
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
Client POST /xrpc/{method} + session cookie or Bearer token
  -> Claims extractor (cookie, API key, or service auth JWT)
  -> xrpc::xrpc_post()
  -> LexiconRegistry lookup (must be Procedure type)
  -> If Lua script attached: execute script (has access to Record API)
  -> Else: default create/update (auto-detect based on uri field)
  -> Restore OAuth session from atrium store (by DID)
  -> atrium handles DPoP proof generation and token refresh
  -> Proxy to user's PDS (createRecord or putRecord)
  -> Upsert record locally
  -> Forward PDS response
```

### Admin endpoints

```
Client request + session cookie or Bearer token
  -> AdminAuth extractor:
     1. Claims validation (cookie, API key, or service auth JWT)
     2. DID lookup in users table (auto-bootstrap super user if empty)
     3. Permission check (403 if missing required permission)
  -> Admin handler
  -> JSON response
```

## Data flow

### Real-time indexing

```
Jetstream WebSocket connection (jetstream::spawn)
  -> Collection filters built from indexed lexicons and applied to subscription URL
  -> Reconnects on collection filter changes (lexicon add/remove)
  -> Record commit events:
     create/update -> UPSERT into records table
     delete        -> DELETE from records table
  -> Lexicon schema events (com.atproto.lexicon.schema):
     -> Update tracked network lexicons in DB and registry
  -> Cursor persisted to instance_settings for resume on reconnect
```

### Backfill

```
POST /admin/backfill
  -> Create backfill_jobs record (status = running)
  -> Relay listReposByCollection -> list of DIDs (paginated)
  -> For each DID: resolve PDS via PLC, listRecords from that PDS (paginated)
  -> UPSERT each record into records table
  -> Update processed_repos / total_records counters
  -> Mark job as completed (or failed with error message)
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

### `users`

| Column         | Type          | Description                                      |
| -------------- | ------------- | ------------------------------------------------ |
| `id`           | uuid (PK)     |                                                  |
| `did`          | text (unique) | User's AT Protocol DID                           |
| `is_super`     | boolean       | Whether this is the super user (only one allowed)|
| `created_at`   | timestamptz   |                                                  |
| `last_used_at` | timestamptz   | Updated on each authenticated request            |

### `user_permissions`

| Column       | Type        | Description                                  |
| ------------ | ----------- | -------------------------------------------- |
| `user_id`    | uuid (FK)   | References `users.id`                        |
| `permission` | text        | Permission string (e.g. `lexicons:create`)   |
| (PK)         |             | Composite primary key: (`user_id`, `permission`) |

### `api_keys`

| Column       | Type        | Description                                  |
| ------------ | ----------- | -------------------------------------------- |
| `id`         | uuid (PK)   |                                              |
| `user_id`    | uuid (FK)   | References `users.id`                        |
| `name`       | text        | Descriptive label                            |
| `key_hash`   | text        | SHA-256 hash of the full key                 |
| `key_prefix` | text        | First 11 characters for display              |
| `permissions`| text[]      | Permissions granted to this key              |
| `created_at` | timestamptz |                                              |
| `last_used_at`| timestamptz|                                              |
| `revoked_at` | timestamptz | Set when revoked (soft delete)               |

### `oauth_sessions`

| Column         | Type        | Description                                  |
| -------------- | ----------- | -------------------------------------------- |
| `did`          | text (PK)   | User's AT Protocol DID                       |
| `session_data` | text        | Serialized OAuth session (managed by atrium) |
| `created_at`   | timestamptz |                                              |
| `updated_at`   | timestamptz |                                              |

### `oauth_state`

| Column       | Type        | Description                                  |
| ------------ | ----------- | -------------------------------------------- |
| `state_key`  | text (PK)   | OAuth state parameter                        |
| `state_data` | text        | Serialized state (managed by atrium)         |
| `created_at` | timestamptz |                                              |

### `instance_settings`

| Column       | Type        | Description                                  |
| ------------ | ----------- | -------------------------------------------- |
| `key`        | text (PK)   | Setting name (e.g. `app_name`)               |
| `value`      | text        | Setting value                                |
| `updated_at` | timestamptz | Last modified                                |

### `event_logs`

| Column       | Type        | Description                                  |
| ------------ | ----------- | -------------------------------------------- |
| `id`         | uuid (PK)   |                                              |
| `event_type` | text        | Category.action format (e.g. `user.created`) |
| `severity`   | text        | `info`, `warn`, or `error`                   |
| `actor_did`  | text        | DID of the user who triggered the event      |
| `subject`    | text        | What was affected (DID, NSID, URI, etc.)     |
| `detail`     | jsonb       | Event-specific data                          |
| `created_at` | timestamptz |                                              |

### `script_variables`

| Column       | Type        | Description                                  |
| ------------ | ----------- | -------------------------------------------- |
| `key`        | text (PK)   | Variable name                                |
| `value`      | text        | Variable value (encrypted at rest)           |
| `created_at` | timestamptz |                                              |
| `updated_at` | timestamptz |                                              |

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

# All tests including end-to-end (SQLite by default)
cargo test

# Or run against Postgres
docker compose -f docker-compose.test.yml up -d
TEST_DATABASE_URL=postgres://happyview:happyview@localhost:5433/happyview_test cargo test
docker compose -f docker-compose.test.yml down
```

End-to-end tests use `wiremock` to mock external services (PLC directory, PDSes) and a real database for full integration coverage. By default tests use SQLite; set `TEST_DATABASE_URL` to a Postgres connection string to test against Postgres.
