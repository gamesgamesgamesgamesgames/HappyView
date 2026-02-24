# Backfill

When you add a new record-type lexicon, HappyView starts indexing new records from that moment via [Tap](https://github.com/bluesky-social/indigo/tree/main/cmd/tap). But what about records that already exist on the network? That's what backfill does: HappyView discovers repos via the relay and delegates the actual record fetching to Tap.

## When backfill runs

- **Automatically** when a record-type lexicon is uploaded with `backfill: true` (the default). See [Lexicons - Backfill flag](lexicons#backfill-flag).
- **Manually** via `POST /admin/backfill` or the [dashboard](../getting-started/dashboard). You can scope a manual backfill to a specific collection, a specific DID, or both.

See the [admin API](../reference/admin-api#backfill) for endpoint details.

## How it works

1. **Determine target collections**: uses the specified collection, or all record lexicons with `backfill: true`
2. **Discover DIDs**: HappyView calls the relay's `com.atproto.sync.listReposByCollection` to find repos that contain records for each target collection (paginated, 1000 per page)
3. **Delegate to Tap**: HappyView sends discovered DIDs to Tap in batches of 1000 via its `/repos/add` endpoint
4. **Tap fetches records**: Tap handles the actual record fetching from each user's PDS and delivers them to HappyView via the WebSocket channel

## Job lifecycle

HappyView marks a backfill job as "completed" once it finishes discovering repos and handing DIDs off to Tap (steps 1-3). This does **not** mean Tap has finished processing all the records. Tap works through them asynchronously after the handoff.

To see whether Tap is still working through the backlog, check the Tap stats on the dashboard's Backfill page or via `GET /admin/tap/stats`. The **outbox buffer** indicates how many events are still queued for delivery; a high number means Tap is actively processing.

## Re-running backfills

Backfill jobs are idempotent. Running a backfill for a collection that's already been backfilled will re-discover repos and send them to Tap again. Tap deduplicates repos it already knows about, so re-running a backfill is safe and useful for catching repos that were added to the network since the last run.

## Next steps

- [Lexicons](lexicons#backfill-flag): Control whether lexicons trigger backfill on upload
- [Admin API](../reference/admin-api#backfill): Full reference for backfill endpoints
- [Admin API - Tap Stats](../reference/admin-api#tap-stats): Monitor Tap's processing progress
