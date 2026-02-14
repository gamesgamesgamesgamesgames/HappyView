# HappyView

HappyView is a lexicon-driven ATProto AppView. Upload lexicon definitions at runtime and HappyView dynamically generates XRPC query and procedure endpoints, indexes records from the network via Jetstream, and proxies writes to users' PDSes --- no restart required.

## How it fits together

```
Jetstream ──> HappyView ──> PostgreSQL
                 │
     ┌───────────┼───────────┐
     │           │           │
   Clients     AIP        PDSes
              (OAuth)   (user repos)
```

- **Jetstream** pushes real-time record events. HappyView subscribes to the collections defined by uploaded lexicons and indexes records into Postgres.
- **AIP** (ATProto Identity Provider) handles OAuth 2.1 with PKCE. HappyView validates tokens by calling AIP's `/oauth/userinfo` endpoint.
- **PDSes** store user data. HappyView proxies writes and blob uploads to each user's PDS using DPoP-authenticated requests.
- **Clients** talk to HappyView's XRPC and admin APIs. Any ATProto-compatible client can connect.

## Docs

- [Quickstart](quickstart.md) - get a local instance running
- [Configuration](configuration.md) - environment variables reference
- [Deployment](deployment.md) - Docker, production, TLS
- [Lexicons](lexicons.md) - uploading and managing lexicon definitions
- [Network Lexicons](network-lexicons.md) - loading lexicons from the ATProto network
- [Backfill](backfill.md) - bulk-indexing historical records
- [XRPC API](xrpc-api.md) - query and procedure endpoints
- [Admin API](admin-api.md) - manage lexicons, backfills, and admins
- [Architecture](architecture.md) - internals for contributors
