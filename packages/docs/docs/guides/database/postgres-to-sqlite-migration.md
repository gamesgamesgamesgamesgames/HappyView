# Migrating from Postgres to SQLite

This guide covers migrating an existing HappyView deployment from Postgres to SQLite. If you are staying on Postgres, no action is required.

## Overview

HappyView now defaults to SQLite and writes all internal SQL in SQLite syntax. When running against Postgres, HappyView translates queries automatically. However, if you have **Lua scripts** that contain raw Postgres SQL, those scripts need to be updated to use SQLite syntax instead.

## Step 1: Export your data

Back up your Postgres database before making any changes:

```sh
pg_dump -U happyview happyview > happyview_backup.sql
```

## Step 2: Update environment variables

Change your `.env` to use SQLite:

```sh
# Before
DATABASE_URL=postgres://happyview:happyview@localhost/happyview

# After
DATABASE_URL=sqlite://data/happyview.db?mode=rwc
```

If you had `DATABASE_BACKEND` set, update it as well:

```sh
DATABASE_BACKEND=sqlite
```

## Step 3: Migrate Lua scripts

If you have Lua scripts with raw SQL queries, they need to be converted from Postgres syntax to SQLite syntax. A codemod tool is provided to automate this.

### Run the codemod tool

```sh
cargo run --bin migrate-lua-sql -- /path/to/lua/scripts
```

The tool scans all `.lua` files in the given directory and rewrites Postgres SQL patterns to SQLite equivalents.

### What the codemod converts automatically

- `$1`, `$2`, etc. parameter placeholders to `?`
- JSON operators (`->`, `->>`) and `::jsonb` casts to `json_extract()` calls
- `ILIKE` to `LIKE` (SQLite `LIKE` is case-insensitive for ASCII by default)
- `NOW()` to `datetime('now')`
- `NOW() + INTERVAL '...'` / `NOW() - INTERVAL '...'` to `datetime('now', '...')`
- `TRUE`/`FALSE` literals to `1`/`0`

### What it flags for manual review

The tool prints warnings for patterns it cannot convert automatically:

- JSONB `?` (contains-key) operator — consider using `json_each()` with an `EXISTS` subquery
- `make_interval()` — Postgres-specific, needs manual conversion
- `SIMILAR TO` — use `LIKE` or `GLOB` instead
- `ANY()` / `ALL()` array operators — no direct SQLite equivalent
- Type casts other than `::jsonb` (e.g., `::text`, `::integer`) — may need manual conversion to `CAST(... AS ...)`

Review the flagged lines and update them manually.

## Step 4: Import data into SQLite

Start HappyView with the new `DATABASE_URL`. It will create the SQLite database and run migrations automatically. If you need to import existing records, use the backfill feature to re-index from the network:

1. Start HappyView with the new SQLite `DATABASE_URL`
2. Upload your lexicons via the dashboard or admin API
3. Run a backfill for each collection (dashboard or `POST /admin/backfill`)

For small datasets, this is the simplest approach since backfill fetches all records fresh from the network.

## Step 5: Update Docker Compose (if applicable)

If you were running Postgres via Docker Compose, you can now comment out the `postgres` service since it is no longer needed. See the [database setup guide](database-setup.md#docker-compose) for details.

## Rollback

To switch back to Postgres, revert your `DATABASE_URL` to the Postgres connection string. Your Postgres database remains unchanged — HappyView does not modify it during the migration to SQLite.

## Next steps

- [SQLite → Postgres migration](sqlite-to-postgres-migration.md) — migrate in the opposite direction
- [Database setup](database-setup.md) — choose between SQLite and Postgres for new instances
- [Backfill](backfill.md) — re-index records from the network after switching backends
- [Lua scripting](scripting.md) — write SQL that works against either backend
