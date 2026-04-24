# Labelers

Labelers are external services that apply content labels to records. They operate out-of-band — labeler data does not appear in repos or flow through relays. HappyView can subscribe to labelers and store the labels they emit, making them available on records in the admin dashboard and via Lua scripts.

## How labelers work

A labeler is identified by its DID. When you subscribe to a labeler, HappyView connects directly to the labeler's WebSocket and streams label events in real time. Each label targets a specific record URI and carries a value like `nudity`, `spam`, or any custom string the labeler defines.

Labels are stored in a `labels` table in the database. HappyView tracks a cursor per labeler subscription so it can resume from where it left off after a restart.

Records can also have **self-labels** — labels applied by the record's author and embedded directly in the record's `labels.values` array. These are not managed by external labelers but are displayed alongside external labels in the dashboard.

## Adding a labeler

1. Go to **Settings > Labelers** in the dashboard sidebar
2. Click **Add Labeler**
3. Enter the labeler's DID (e.g., `did:plc:ar7c4by46qjdydhdevvrndac`)
4. Click **Add**

HappyView begins consuming labels from the labeler immediately. The subscription appears in the table with an `active` status.

You can also add a labeler via the API:

```sh
curl -X POST http://localhost:3000/admin/labelers \
  -H "$AUTH" \
  -H "Content-Type: application/json" \
  -d '{ "did": "did:plc:ar7c4by46qjdydhdevvrndac" }'
```

## Pausing and resuming

You can pause a labeler subscription to temporarily stop consuming labels without losing your cursor position. Click the pause icon next to the labeler in the table, or use the API:

```sh
curl -X PATCH http://localhost:3000/admin/labelers/did:plc:ar7c4by46qjdydhdevvrndac \
  -H "$AUTH" \
  -H "Content-Type: application/json" \
  -d '{ "status": "paused" }'
```

Resume by clicking the play icon or sending `{ "status": "active" }`.

## Deleting a labeler

Deleting a labeler removes the subscription **and all labels it has emitted**. This cannot be undone.

1. Click the trash icon next to the labeler
2. Confirm in the dialog

Or via the API:

```sh
curl -X DELETE http://localhost:3000/admin/labelers/did:plc:ar7c4by46qjdydhdevvrndac \
  -H "$AUTH"
```

## Labels on records

Labels appear in the **Labels** column on the Records page as color-coded badges:

- **Red** — content warnings: `nudity`, `sexual`, `graphic-media`, `violence`, `gore`
- **Amber** — moderation labels: `spam`, `impersonation`
- **Neutral** — everything else

Self-labels (applied by the record author) use an outline badge style to distinguish them from external labels. Hover over a badge to see the source labeler's DID.

Labels are also available in the records API response and in Lua scripts via the [`atproto.get_labels` and `atproto.get_labels_batch`](../../reference/lua/atproto-api.md#atprotoget_labels) functions.

## Using labels in your AppView

Labeler subscriptions give your AppView access to content moderation signals without building your own moderation system. Some ways to use them:

- **Content filtering**: Use labels in query scripts to exclude or down-rank flagged content. Check labels with `atproto.get_labels` and filter results before returning them.
- **Moderation dashboards**: Display labels alongside records in your admin dashboard to review flagged content. Labels appear automatically on the Records page once a labeler is subscribed.
- **Custom labelers**: You can subscribe to any labeler that implements the atproto labeler spec, including community-run labelers or one you operate yourself for domain-specific moderation (e.g. labeling game content by age rating).

## Permissions

| Action              | Permission        |
| ------------------- | ----------------- |
| View labeler list   | `labelers:read`   |
| Add or pause/resume | `labelers:create` |
| Delete a labeler    | `labelers:delete` |

## Next steps

- [Admin API — Labelers](../../reference/admin/labelers.md) — full endpoint documentation
- [atproto API](../../reference/lua/atproto-api.md) — access labels in Lua scripts with `get_labels` and `get_labels_batch`
- [Permissions](../admin/permissions.md) — manage user access to labeler operations
