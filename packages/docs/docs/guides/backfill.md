# Backfill

When you add a new record-type lexicon, HappyView starts indexing new records from that moment via [Jetstream](https://github.com/bluesky-social/jetstream). But what about records that already exist on the network? That's what backfill does: HappyView discovers repos via the relay and fetches records directly from each user's PDS.

## When backfill runs

- **Automatically** when a record-type lexicon is uploaded with `backfill: true` (the default). See [Lexicons - Backfill flag](lexicons.md#backfill-flag).
- **Manually** via `POST /admin/backfill` or the [dashboard](../getting-started/dashboard.md). You can scope a manual backfill to a specific collection, a specific DID, or both.

See the [admin API](../reference/admin/backfill.md) for endpoint details.

## How it works

1. **Determine target collections**: uses the specified collection, or all record lexicons with `backfill: true`
2. **Discover DIDs**: HappyView calls the relay's `com.atproto.sync.listReposByCollection` to find repos that contain records for each target collection (paginated)
3. **Resolve each PDS**: for each discovered DID, HappyView resolves the DID document via PLC to find the user's PDS endpoint
4. **Fetch records**: HappyView calls `com.atproto.repo.listRecords` on each PDS for the target collection (paginated) and upserts each record into the local database
5. **Track progress**: counters for `processed_repos` and `total_records` are updated as the job runs

## Job lifecycle

A backfill job moves through `pending → running → completed` (or `failed`). Unlike earlier versions of HappyView that relied on Tap, the job is only marked `completed` once every discovered repo has been processed end-to-end — there is no separate downstream queue. Progress is visible in real time on the dashboard's Backfill page.

If a job fails midway, the `error` field contains the failure reason. Re-running the backfill resumes from scratch but is idempotent (records are upserted by URI).

## Re-running backfills

Re-running a backfill for a collection that's already been backfilled is safe. Each record is upserted by its AT URI, so existing records are refreshed in place and any new records discovered since the last run are added. This also picks up new repos that have joined the network since the previous backfill.

## Restoring deleted records

Deleting records from HappyView (via the dashboard or API) only removes them from the local database — the records still exist on the AT Protocol network. To restore deleted records, create a backfill job for the affected collection. The backfill will re-discover the repos and re-fetch all records from each PDS, restoring any that were previously deleted.

## Next steps

- [Lexicons](lexicons.md#backfill-flag): Control whether lexicons trigger backfill on upload
- [Admin API — Backfill](../reference/admin/backfill.md): Full reference for backfill endpoints
