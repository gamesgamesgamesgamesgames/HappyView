# Admin API: Event Logs

HappyView logs system events — lexicon changes, record operations, script errors, user actions, and more. See the [Event Logs guide](../../guides/admin/event-logs.md) for details on event types and retention.

```sh
# All examples assume $TOKEN is an API key (hv_...)
AUTH="Authorization: Bearer $TOKEN"
```

## List event logs

```
GET /admin/events
```

```sh
curl "http://127.0.0.1:3000/admin/events?severity=error&limit=10" -H "$AUTH"
```

| Param        | Type   | Required | Description                                                           |
| ------------ | ------ | -------- | --------------------------------------------------------------------- |
| `event_type` | string | no       | Filter by exact event type (e.g. `script.error`)                      |
| `category`   | string | no       | Filter by category prefix (e.g. `lexicon` matches all lexicon events) |
| `severity`   | string | no       | Filter by severity: `info`, `warn`, or `error`                        |
| `subject`    | string | no       | Filter by subject (lexicon ID, record URI, admin DID, etc.)           |
| `cursor`     | string | no       | Pagination cursor (ISO 8601 timestamp from previous response)         |
| `limit`      | number | no       | Results per page (default `50`, max `100`)                            |

**Response**: `200 OK`

```json
{
  "events": [
    {
      "id": "550e8400-e29b-41d4-a716-446655440000",
      "event_type": "script.error",
      "severity": "error",
      "actor_did": "did:plc:abc123",
      "subject": "com.example.feed.like",
      "detail": {
        "error": "attempt to index nil value",
        "script_source": "function handle() ... end",
        "input": { "status": "hello" },
        "caller_did": "did:plc:abc123",
        "method": "com.example.feed.like"
      },
      "created_at": "2026-03-01T12:00:00Z"
    }
  ],
  "cursor": "2026-03-01T11:59:00Z"
}
```

Events are returned in reverse chronological order (newest first). Pass the `cursor` value from the response to fetch the next page.
