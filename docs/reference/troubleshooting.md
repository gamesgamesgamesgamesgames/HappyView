# Troubleshooting

Common issues and how to resolve them.

## XRPC endpoint returns 404

**Symptom**: `GET /xrpc/your.method.name` returns `{"error": "method not found"}`.

**Causes**:

- The lexicon hasn't been uploaded yet. Check with `GET /admin/lexicons` or the [dashboard](../getting-started/dashboard.md).
- The lexicon's `defs.main.type` doesn't match the HTTP method. Queries are `GET`, procedures are `POST`.
- The NSID in the URL doesn't match the `id` field in the uploaded lexicon JSON.

## Queries return empty results

**Symptom**: The XRPC query endpoint returns `{"records": []}` even though records should exist.

**Causes**:

- The query lexicon is missing a `target_collection`. Without it, the query doesn't know which records to read. See [Lexicons - target_collection](../guides/lexicons.md#target-collection).
- The record-type lexicon hasn't finished backfilling. Check backfill status with `GET /admin/backfill/status` or the dashboard.
- Records exist on the network but HappyView hasn't indexed them yet. Tap only picks up new events from when the collection filter was added. Use [backfill](../guides/backfill.md) for historical records.

## Procedure returns 401 Unauthorized

**Symptom**: `POST /xrpc/your.method.name` returns `{"error": "..."}` with status 401.

**Causes**:

- The `Authorization: Bearer <token>` header is missing or malformed.
- The token has expired or is invalid. Tokens are validated against AIP's `/oauth/userinfo` endpoint.
- AIP is unreachable. Check that `AIP_URL` is set correctly and the AIP service is running.

For AIP-specific issues, see the [AIP documentation](https://github.com/graze-social/aip).

## Admin endpoints return 403 Forbidden

**Symptom**: Admin API calls return `{"error": "forbidden"}`.

**Causes**:

- Your DID is not in the admins table. Ask an existing admin to add you via `POST /admin/admins`.
- If this is a fresh deployment with no admins, the first authenticated request to any admin endpoint automatically bootstraps you as admin. Make sure you're sending a valid Bearer token.

## Lua script errors

**Symptom**: An XRPC endpoint returns `{"error": "script execution failed"}` or `{"error": "script exceeded execution time limit"}`.

**What to do**:

1. Check the server logs: the full error message is logged at error level but not exposed to the client.
2. Use `log("message")` in your script to trace execution. Output appears in server logs at debug level (requires `RUST_LOG` to include debug).
3. If you hit the execution limit, your script likely has an infinite loop or is processing too much data. See [Lua Scripting - Sandbox](../guides/scripting.md#sandbox).

See [Lua Scripting - Debugging](../guides/scripting.md#debugging) for more.

## Backfill job stuck in "pending" or "running"

**Symptom**: A backfill job doesn't progress or stays in `pending`.

**Causes**:

- The backfill worker processes one job at a time. If another job is running, yours will wait.
- The relay (`RELAY_URL`) may be unreachable or slow to respond. Check connectivity.
- Individual PDS fetches can fail silently. The worker logs warnings and continues. Check server logs for details.

See [Backfill](../guides/backfill.md) for how the process works.

## Records not appearing in real time

**Symptom**: New records created on the network don't show up in queries.

**Causes**:

- HappyView receives real-time events via [Tap](https://github.com/bluesky-social/indigo/tree/main/cmd/tap). Make sure Tap is running and connected to HappyView. See the [Tap documentation](https://github.com/bluesky-social/indigo/tree/main/cmd/tap) for configuration.
- No record-type lexicon exists for the collection. HappyView only indexes collections that have a corresponding record-type lexicon.
- The Tap connection hasn't synced the new collection filter after a lexicon change. This should happen automatically. Check server logs for connection errors.

## OAuth or login issues

OAuth is handled entirely by [AIP](https://github.com/graze-social/aip). If users can't log in or tokens aren't working:

1. Verify AIP is running and reachable at the configured `AIP_URL`.
2. Check that AIP has valid signing keys configured (`OAUTH_SIGNING_KEYS`).
3. Check that both HappyView and AIP have public URLs assigned (required for OAuth callbacks).

See the [AIP documentation](https://github.com/graze-social/aip) for setup and debugging.

## Database connection errors

**Symptom**: HappyView fails to start or returns 500 errors.

**Causes**:

- `DATABASE_URL` is not set or points to an unreachable Postgres instance.
- The database user doesn't have sufficient permissions. HappyView needs to create tables (migrations run automatically on startup).
- Postgres version is too old. HappyView requires Postgres 17+.

See [Configuration](../getting-started/configuration.md) for environment variable details.
