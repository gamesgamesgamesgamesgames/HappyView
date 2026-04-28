# Event Logs

HappyView maintains an internal event log that records system activity — lexicon changes, record operations, Lua script executions and errors, user actions, API key events, backfill jobs, and Jetstream connectivity. Events are stored in the database and queryable via the [admin API](../../reference/admin/events.md).

## Event types

Events follow a `category.action` naming convention. Each event has a severity level (`info`, `warn`, or `error`), an optional `actor_did` (the user who triggered it), an optional `subject` (what was affected), and a `detail` JSON object with event-specific data.

### Lexicon events

| Event Type | Severity | Subject | Detail |
|---|---|---|---|
| `lexicon.created` | info | Lexicon NSID | `revision`, `has_script`, `source` |
| `lexicon.updated` | info | Lexicon NSID | `revision`, `has_script`, `source` |
| `lexicon.deleted` | info | Lexicon NSID | — |

Logged when lexicons are uploaded, updated, or deleted via the [admin API](../../reference/admin/lexicons.md). The `actor_did` is the user who performed the action.

### Record events

| Event Type | Severity | Subject | Detail |
|---|---|---|---|
| `record.created` | info | Record AT URI | `collection`, `did`, `rkey` |
| `record.deleted` | info | Record AT URI | `collection`, `did`, `rkey` |

Logged when records are received from Jetstream and stored or removed from the local database. These are system-triggered events (`actor_did` is null). If a database error occurs during the operation, the same event type is logged with `error` severity and the error message is included in the detail.

### Script events

| Event Type | Severity | Subject | Detail |
|---|---|---|---|
| `script.executed` | info | Method NSID | `method`, `caller_did`, `duration_ms` |
| `script.error` | error | Method NSID | `error`, `script_source`, `input`, `caller_did`, `method` |

Logged when Lua scripts run for XRPC query or procedure endpoints. Script errors capture the full context needed to reproduce and debug the issue: the error message, the complete Lua script source, the input that triggered it, and the caller's DID.

:::note
For query scripts (unauthenticated), `caller_did` and `input` are omitted from the detail since queries don't have an authenticated user or request body.
:::

### User events

| Event Type | Severity | Subject | Detail |
|---|---|---|---|
| `user.created` | info | New user DID | `template` (if used) |
| `user.deleted` | info | Removed user ID | — |
| `user.bootstrapped` | info | Bootstrapped user DID | — |
| `user.permissions_updated` | info | User ID | `granted`, `revoked` |
| `user.super_transferred` | warn | New super user ID | `from_user_id` |

The `user.bootstrapped` event is logged when the first user is auto-promoted to super user (see [Auth - Auto-bootstrap](../../reference/admin/admin-api.md#auth)).

### Auth events

| Event Type | Severity | Subject | Detail |
|---|---|---|---|
| `auth.permission_denied` | error | Endpoint path | `required_permission`, `user_id` |

Logged when a user attempts to access an endpoint they don't have permission for.

### API Key events

| Event Type | Severity | Subject | Detail |
|---|---|---|---|
| `api_key.created` | info | Key ID | `name`, `permissions` |
| `api_key.revoked` | info | Key ID | `name` |

### Script Variable events

| Event Type | Severity | Subject | Detail |
|---|---|---|---|
| `script_variable.upserted` | info | Variable key | — |
| `script_variable.deleted` | info | Variable key | — |

### Hook events

| Event Type | Severity | Subject | Detail |
|---|---|---|---|
| `hook.executed` | info | Record AT URI | `lexicon_id` |
| `hook.dead_lettered` | error | Record AT URI | `lexicon_id`, `error` |

Logged when [index hooks](../indexing/index-hooks.md) run. Dead-lettered events indicate a hook failed all retry attempts. You can manage dead letters from the **Data > Dead Letters** page in the dashboard — see [Dead Letters](#dead-letters) below.

### Backfill events

| Event Type | Severity | Subject | Detail |
|---|---|---|---|
| `backfill.started` | info | Collection NSID | `job_id` |
| `backfill.completed` | info | Collection NSID | `job_id`, `total_repos` |
| `backfill.failed` | error | Collection NSID | `job_id`, `error` |

See [Backfill](../indexing/backfill.md) for background on backfill jobs.

### Jetstream events

| Event Type | Severity | Subject | Detail |
|---|---|---|---|
| `jetstream.connected` | info | — | `url` |
| `jetstream.disconnected` | warn | — | `reason` |

Logged when the WebSocket connection to [Jetstream](https://github.com/bluesky-social/jetstream) is established or lost.

## Querying events

Use the admin API to query event logs with filters:

```sh
# Get all errors
curl "http://127.0.0.1:3000/admin/events?severity=error" -H "$AUTH"

# Get script errors for a specific lexicon
curl "http://127.0.0.1:3000/admin/events?event_type=script.error&subject=com.example.feed.like" -H "$AUTH"

# Get all lexicon-related events
curl "http://127.0.0.1:3000/admin/events?category=lexicon" -H "$AUTH"

# Paginate through results
curl "http://127.0.0.1:3000/admin/events?limit=20&cursor=2026-03-01T11:59:00Z" -H "$AUTH"
```

See the [Admin API reference](../../reference/admin/events.md#list-event-logs) for full parameter documentation.

## Retention

Event logs are automatically cleaned up based on the `EVENT_LOG_RETENTION_DAYS` environment variable (default: 30 days). A background task runs hourly to delete events older than the configured retention period.

Set `EVENT_LOG_RETENTION_DAYS=0` to disable automatic cleanup and keep logs indefinitely.

See [Configuration](../../getting-started/configuration.md) for all environment variables.

## Dead Letters

When an index hook fails after all retry attempts, the event is stored in the dead letters queue. You can manage dead letters from the **Data > Dead Letters** page in the dashboard.

From the dead letters page you can:

- **Retry Hook** — replay the stored record through the index hook (use after fixing a hook script)
- **Re-index** — fetch the record fresh from the PDS and run it through the full indexing pipeline (use when the record may have changed)
- **Dismiss** — mark the dead letter as resolved without retrying

Bulk actions are available for selected rows or all entries matching the current filters.

## Next steps

- [Admin API — Event Logs](../../reference/admin/events.md) — full query parameters and response format
- [Permissions](permissions.md) — control which users can read event logs
- [Troubleshooting](../../reference/troubleshooting.md) — using event logs to diagnose issues
