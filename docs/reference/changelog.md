# Changelog

## v1.9.0 — Event Logs

- **Event logging** — system-wide audit trail for lexicon changes, record operations, Lua script executions/errors, admin actions, backfill jobs, and Tap connectivity
- **`GET /admin/events`** — query event logs with filtering by event type, category, severity, and subject, with cursor pagination
- **Lua error context** — script errors capture full debugging context: error message, script source, input payload, and caller DID
- **Automatic retention cleanup** — configurable via `EVENT_LOG_RETENTION_DAYS` (default 30 days)

## v1.8.0 — Advanced Queries

- **`db.backlinks()`** — find records that reference a given AT URI
- **`db.raw()`** — run raw read-only SQL with parameterized queries and automatic column type mapping

## v1.7.1 — Patch

- Fixed Docker Compose database URLs for local dev

## v1.7.0 — Lua DB API Improvements

- **`toarray()`** utility — force Lua tables to serialize as JSON arrays (fixes empty `{}` vs `[]`)
- **`db.search()`** — text search on record fields with relevance ranking
- **Array serialization fix** — `db.query()` and `db.search()` now always return proper arrays for `records`

## v1.6.2 — Patch

- Fixed auth: use original auth scheme instead of hardcoded DPoP

## v1.6.1 — Patch

- Fixed broken dynamic page routes

## v1.6.0 — Record Management

- **Delete records** from the dashboard and API (individual and bulk collection deletion)
- **"View Records" buttons** on lexicon pages
- Bug fixes: backfill now loads previously deleted records, empty collections shown in dropdown

## v1.5.1 — Patch

- Removed backfill toggle from query/procedure lexicons (only applies to record lexicons)

## v1.5.0 — Lua Scripting & Dashboard Overhaul

- **Lua scripting** — attach custom Lua scripts to query and procedure lexicons
- **Docusaurus docs site** with GitHub Pages deploy
- **Dark mode** for the dashboard
- **Records table** reworked with dynamic columns, column visibility, and better scrolling
- **Backfill stats tracking**
- **Network and local lexicons merged** into a unified view
- **Shiki code highlighting** in the dashboard
- Bug fixes: rogue record storage, collection dropdown, dynamic page builds
