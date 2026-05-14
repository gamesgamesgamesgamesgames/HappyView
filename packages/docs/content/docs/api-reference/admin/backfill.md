---
title: "Backfill"
---

Create and monitor historical backfill jobs. See the [Backfill guide](../../guides/backfill.md) for background.

```ts tab="TypeScript" tab-group="language"
const TOKEN = "hv_..."; // your API key
const headers = { Authorization: `Bearer ${TOKEN}` };
```
```js tab="JavaScript" tab-group="language"
const TOKEN = "hv_..."; // your API key
const headers = { Authorization: `Bearer ${TOKEN}` };
```
```rust tab="Rust" tab-group="language"
let token = "hv_..."; // your API key
```
```go tab="Go" tab-group="language"
token := "hv_..." // your API key
```
```sh tab="cURL" tab-group="language"
# All examples assume $TOKEN is an API key (hv_...)
AUTH="Authorization: Bearer $TOKEN"
```

## Create a backfill job

```
POST /admin/backfill
```

```ts tab="TypeScript" tab-group="language"
interface BackfillJob {
  id: string;
  status: string;
}

const response = await fetch("http://127.0.0.1:3000/admin/backfill", {
  method: "POST",
  headers: {
    ...headers,
    "Content-Type": "application/json",
  },
  body: JSON.stringify({
    collection: "xyz.statusphere.status",
  }),
});
const data: BackfillJob = await response.json();
```
```js tab="JavaScript" tab-group="language"
const response = await fetch("http://127.0.0.1:3000/admin/backfill", {
  method: "POST",
  headers: {
    ...headers,
    "Content-Type": "application/json",
  },
  body: JSON.stringify({
    collection: "xyz.statusphere.status",
  }),
});
const data = await response.json();
```
```rust tab="Rust" tab-group="language"
let client = reqwest::Client::new();
let response = client
    .post("http://127.0.0.1:3000/admin/backfill")
    .bearer_auth(token)
    .json(&serde_json::json!({
        "collection": "xyz.statusphere.status"
    }))
    .send()
    .await?;
let data: serde_json::Value = response.json().await?;
```
```go tab="Go" tab-group="language"
body := bytes.NewBufferString(`{"collection": "xyz.statusphere.status"}`)
req, _ := http.NewRequest("POST", "http://127.0.0.1:3000/admin/backfill", body)
req.Header.Set("Authorization", "Bearer "+token)
req.Header.Set("Content-Type", "application/json")
resp, err := http.DefaultClient.Do(req)
```
```sh tab="cURL" tab-group="language"
curl -X POST http://127.0.0.1:3000/admin/backfill \
  -H "$AUTH" \
  -H "Content-Type: application/json" \
  -d '{ "collection": "xyz.statusphere.status" }'
```

| Field        | Type   | Required | Description                                                |
| ------------ | ------ | -------- | ---------------------------------------------------------- |
| `collection` | string | no       | Limit to a single collection (backfills all if omitted)    |
| `did`        | string | no       | Limit to a single DID (discovers all via relay if omitted) |

**Response**: `201 Created`

```json
{
  "id": "550e8400-e29b-41d4-a716-446655440000",
  "status": "running"
}
```

## Cancel a backfill job

```
POST /admin/backfill/{id}/cancel
```

Requests cancellation of a running backfill job. The job status transitions to `cancelling` immediately; the background worker will stop at its next checkpoint and set the final status to `cancelled`. See the [Backfill guide](../../guides/backfill.md#cancelling-a-job) for details on the two-phase process.

```ts tab="TypeScript" tab-group="language"
const response = await fetch(
  `http://127.0.0.1:3000/admin/backfill/${jobId}/cancel`,
  { method: "POST", headers },
);
const data = await response.json();
```
```js tab="JavaScript" tab-group="language"
const response = await fetch(
  `http://127.0.0.1:3000/admin/backfill/${jobId}/cancel`,
  { method: "POST", headers },
);
const data = await response.json();
```
```rust tab="Rust" tab-group="language"
let response = client
    .post(format!("http://127.0.0.1:3000/admin/backfill/{job_id}/cancel"))
    .bearer_auth(token)
    .send()
    .await?;
let data: serde_json::Value = response.json().await?;
```
```go tab="Go" tab-group="language"
url := fmt.Sprintf("http://127.0.0.1:3000/admin/backfill/%s/cancel", jobID)
req, _ := http.NewRequest("POST", url, nil)
req.Header.Set("Authorization", "Bearer "+token)
resp, err := http.DefaultClient.Do(req)
```
```sh tab="cURL" tab-group="language"
curl -X POST "http://127.0.0.1:3000/admin/backfill/$JOB_ID/cancel" -H "$AUTH"
```

**Response**: `200 OK`

```json
{
  "id": "550e8400-e29b-41d4-a716-446655440000",
  "status": "cancelling"
}
```

Returns `400` if the job is not currently running, or `404` if the job ID is not found.

## List backfill jobs

```
GET /admin/backfill/status
```

```ts tab="TypeScript" tab-group="language"
interface BackfillJob {
  id: string;
  collection: string | null;
  did: string | null;
  status: string;
  stage: string;
  total_repos: number | null;
  processed_repos: number | null;
  total_records: number | null;
  error: string | null;
  started_at: string | null;
  completed_at: string | null;
  created_at: string;
}

const response = await fetch("http://127.0.0.1:3000/admin/backfill/status", {
  headers,
});
const data: BackfillJob[] = await response.json();
```
```js tab="JavaScript" tab-group="language"
const response = await fetch("http://127.0.0.1:3000/admin/backfill/status", {
  headers,
});
const data = await response.json();
```
```rust tab="Rust" tab-group="language"
let response = client
    .get("http://127.0.0.1:3000/admin/backfill/status")
    .bearer_auth(token)
    .send()
    .await?;
let data: serde_json::Value = response.json().await?;
```
```go tab="Go" tab-group="language"
req, _ := http.NewRequest("GET", "http://127.0.0.1:3000/admin/backfill/status", nil)
req.Header.Set("Authorization", "Bearer "+token)
resp, err := http.DefaultClient.Do(req)
```
```sh tab="cURL" tab-group="language"
curl http://127.0.0.1:3000/admin/backfill/status -H "$AUTH"
```

**Response**: `200 OK`

```json
[
  {
    "id": "550e8400-e29b-41d4-a716-446655440000",
    "collection": "xyz.statusphere.status",
    "did": null,
    "status": "completed",
    "stage": "completed",
    "total_repos": 42,
    "processed_repos": 42,
    "total_records": 1000,
    "error": null,
    "started_at": "2025-01-01T00:01:00Z",
    "completed_at": "2025-01-01T00:05:00Z",
    "created_at": "2025-01-01T00:00:00Z"
  }
]
```

The `status` field tracks the overall job state (`running`, `cancelling`, `cancelled`, `completed`, `failed`). The `stage` field tracks the current processing phase (`pending`, `discovering_repos`, `resolving_pds`, `fetching_records`, `completed`, `failed`, `cancelled`).
