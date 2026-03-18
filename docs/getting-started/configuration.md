# Configuration

HappyView is configured via environment variables. A `.env` file in the project root is loaded automatically on startup. See [Deployment](deployment/docker.md) for local setup or [Production Deployment](../reference/production-deployment.md) for production setup.

## Environment variables

| Variable | Required | Default | Description |
|----------|----------|---------|-------------|
| `DATABASE_URL` | yes | --- | Database connection string. SQLite (`sqlite://path/to/db?mode=rwc`) or Postgres (`postgres://user:pass@host/db`) |
| `DATABASE_BACKEND` | no | auto-detected | Force `sqlite` or `postgres`. Auto-detected from `DATABASE_URL` scheme if not set |
| `PUBLIC_URL` | yes | --- | Public-facing URL for HappyView (used for OAuth callbacks, e.g. `https://happyview.example.com`) |
| `SESSION_SECRET` | no | dev default | Secret key for signing session cookies. **Must be set in production** |
| `HOST` | no | `0.0.0.0` | Bind host |
| `PORT` | no | `3000` | Bind port |
| `TAP_URL` | no | `http://localhost:2480` | [Tap](https://github.com/bluesky-social/indigo/tree/main/cmd/tap) instance URL for real-time record streaming and backfill |
| `TAP_ADMIN_PASSWORD` | no | --- | Shared secret for authenticating with Tap's admin endpoints |
| `RELAY_URL` | no | `https://bsky.network` | Relay URL for [backfill](../guides/backfill.md) repo discovery |
| `PLC_URL` | no | `https://plc.directory` | [PLC directory](https://github.com/did-method-plc/did-method-plc) URL for DID resolution |
| `EVENT_LOG_RETENTION_DAYS` | no | `30` | Number of days to keep event logs before automatic cleanup. Set to `0` to disable cleanup |
| `RUST_LOG` | no | `happyview=debug,tower_http=debug` | Log filter (uses `tracing_subscriber::EnvFilter`) |

## Example `.env`

```sh
# SQLite (default — zero setup required)
DATABASE_URL=sqlite://data/happyview.db?mode=rwc
PUBLIC_URL=http://localhost:3000
SESSION_SECRET=change-me-in-production

# Or use Postgres instead:
# DATABASE_URL=postgres://happyview:happyview@localhost/happyview

# Optional overrides
# HOST=0.0.0.0
# PORT=3000
# TAP_URL=http://localhost:2480
# TAP_ADMIN_PASSWORD=your-secret-here
# RELAY_URL=https://bsky.network
# PLC_URL=https://plc.directory
# EVENT_LOG_RETENTION_DAYS=30
# RUST_LOG=happyview=debug,tower_http=debug
```
