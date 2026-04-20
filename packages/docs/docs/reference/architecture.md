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

Queries go through the query handler to the database (SQLite by default, or Postgres). Writes go through the procedure handler to the user's PDS, then HappyView indexes the record locally. Real-time record events stream in via [Jetstream](https://github.com/bluesky-social/jetstream); historical records are backfilled in-process by discovering repos via the relay's `listReposByCollection` and fetching records directly from each PDS.

## Request flow

### Reads (queries)

```mermaid
sequenceDiagram
    participant C as Client
    participant X as xrpc_get()
    participant R as LexiconRegistry
    participant L as Lua Script
    participant D as Database

    C->>X: GET /xrpc/{method}?params
    X->>R: Lookup (must be Query type)
    alt Lua script attached
        R->>L: Execute script
        L->>D: db.query / db.get / db.raw
        D-->>L: Results
        L-->>X: Response table
    else No script
        R->>D: Default SQL query (collection from target_collection)
        D-->>X: Results
    end
    X-->>C: JSON response
```

### Writes (procedures)

```mermaid
sequenceDiagram
    participant C as Client
    participant A as Claims Extractor
    participant X as xrpc_post()
    participant R as LexiconRegistry
    participant L as Lua Script
    participant S as OAuth Session
    participant P as User PDS
    participant D as Database

    C->>A: POST /xrpc/{method} + DPoP auth + X-Client-Key
    A->>X: Validated claims
    X->>R: Lookup (must be Procedure type)
    alt Lua script attached
        R->>L: Execute script (Record API)
        L->>S: Record:save()
    else No script
        R->>S: Default create/update (auto-detect from uri field)
    end
    S->>P: Proxy write (createRecord or putRecord)
    P-->>S: PDS response
    S->>D: Upsert record locally
    S-->>C: Forward PDS response
```

### Admin endpoints

```mermaid
sequenceDiagram
    participant C as Client
    participant A as AdminAuth Extractor
    participant U as Users Table
    participant H as Admin Handler
    participant D as Database

    C->>A: Request + Bearer token
    A->>A: Validate claims (API key or service auth JWT)
    A->>U: DID lookup
    alt Users table empty
        U-->>A: Auto-bootstrap as super user
    else User found
        U-->>A: Load permissions
    end
    A->>A: Permission check (403 if missing)
    A->>H: Authorized request
    H->>D: Database operation
    D-->>H: Result
    H-->>C: JSON response
```

## Data flow

### Real-time indexing

```mermaid
sequenceDiagram
    participant J as Jetstream WebSocket
    participant H as HappyView
    participant D as Database
    participant R as LexiconRegistry

    H->>J: Connect (collection filters from indexed lexicons)
    loop Stream events
        J->>H: Record commit event
        alt create / update
            H->>D: UPSERT into records table
        else delete
            H->>D: DELETE from records table
        end
    end
    J->>H: Lexicon schema event (com.atproto.lexicon.schema)
    H->>D: Update tracked network lexicons
    H->>R: Update in-memory registry
    Note over H,D: Cursor persisted to instance_settings for resume on reconnect
    Note over H,J: Reconnects on collection filter changes (lexicon add/remove)
```

### Backfill

```mermaid
sequenceDiagram
    participant A as Admin
    participant H as HappyView
    participant D as Database
    participant Relay as Relay
    participant PLC as PLC Directory
    participant PDS as User PDS

    A->>H: POST /admin/backfill
    H->>D: Create backfill_jobs record (status = running)
    H->>Relay: listReposByCollection (paginated)
    Relay-->>H: List of DIDs
    loop For each DID
        H->>PLC: Resolve DID document
        PLC-->>H: PDS endpoint
        H->>PDS: listRecords (paginated)
        PDS-->>H: Records
        H->>D: UPSERT each record
        H->>D: Update processed_repos / total_records
    end
    H->>D: Mark job completed (or failed)
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
| `did`          | text (unique) | User's atproto DID                           |
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
| `did`          | text (PK)   | User's atproto DID                       |
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
