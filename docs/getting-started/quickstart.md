# Quickstart

This page walks you through the fastest path to a working HappyView instance. By the end, you'll have an AppView that indexes records from the AT Protocol network and serves XRPC endpoints.

## 1. Deploy HappyView

Pick whichever option fits your situation:

| Option | Best for |
|--------|----------|
| [**Railway**](deployment/railway.md) | Fastest path — one-click deploy of the full stack (HappyView + AIP + Tap + Postgres) |
| [**Docker Compose**](deployment/docker.md) | Local development with the full stack running in containers |
| [**From source**](deployment/other.md) | Running HappyView with `cargo run` and managing dependencies yourself |

If you're just trying HappyView for the first time, start with Railway.

## 2. Log in to the dashboard

Open your HappyView instance in a browser. The built-in [dashboard](dashboard.md) is served at the root URL.

Click **Log in** and authenticate with your AT Protocol identity. On a fresh deployment with no admins configured, the first authenticated request to any admin endpoint automatically bootstraps that user as an admin.

## 3. Add your first lexicon

Lexicons tell HappyView what data to index and what endpoints to serve. The quickest way to get started is to add one from the network:

1. In the dashboard, go to **Lexicons > Add Lexicon > Network**
2. Enter an NSID (e.g. `xyz.statusphere.status`)
3. HappyView resolves the schema from the AT Protocol network and shows a preview
4. Click **Add**

HappyView immediately starts indexing records for that collection. A backfill job is created to fetch historical records, and new records stream in via Tap in real time.

You can also upload lexicons manually via the dashboard or the [admin API](../reference/admin-api.md). See [Lexicons](../guides/lexicons.md) for the full details.

## 4. Verify records are being indexed

Go to the **Dashboard** home page. The stat cards show the total record count and a breakdown by collection. You can also browse indexed records on the **Records** page.

To check backfill progress, go to the **Backfill** page. The Tap stats cards show how many repos and records Tap has processed.

## 5. Query your data

Once you have a record lexicon indexed, add a query lexicon to expose a read endpoint. Go to **Lexicons > Add Lexicon > Local** and create a query lexicon with `target_collection` set to your record collection's NSID.

Without a Lua script, HappyView generates a default query endpoint that supports `limit`, `cursor`, `did`, and `uri` parameters:

```
GET /xrpc/xyz.statusphere.listStatuses?limit=5
```

For custom query logic, attach a [Lua script](../guides/scripting.md).

## Next steps

You now have a working AppView. Here's where to go from here:

- [**Statusphere tutorial**](../tutorials/statusphere.md): end-to-end walkthrough building a complete AppView with record, query, and procedure lexicons
- [**Lexicons guide**](../guides/lexicons.md): target collections, backfill flag, network lexicons
- [**Lua Scripting**](../guides/scripting.md): custom query and procedure logic
- [**Configuration**](configuration.md): environment variables and tuning
- [**Authentication**](authentication.md): how OAuth works and how to get API tokens
