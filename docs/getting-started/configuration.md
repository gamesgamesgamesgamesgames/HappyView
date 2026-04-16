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
| `JETSTREAM_URL` | no | `wss://jetstream1.us-east.bsky.network` | Jetstream WebSocket URL for real-time record streaming |
| `RELAY_URL` | no | `https://bsky.network` | Relay URL for [backfill](../guides/backfill.md) repo discovery |
| `PLC_URL` | no | `https://plc.directory` | [PLC directory](https://github.com/did-method-plc/did-method-plc) URL for DID resolution |
| `STATIC_DIR` | no | `./web/out` | Directory containing the built dashboard static assets |
| `EVENT_LOG_RETENTION_DAYS` | no | `30` | Number of days to keep event logs before automatic cleanup. Set to `0` to disable cleanup |
| `TOKEN_ENCRYPTION_KEY` | no | --- | Base64-encoded 32-byte key for encrypting stored OAuth tokens. **Strongly recommended in production** |
| `DEFAULT_RATE_LIMIT_CAPACITY` | no | `100` | Default token bucket capacity used when registering a new API client |
| `DEFAULT_RATE_LIMIT_REFILL_RATE` | no | `2.0` | Default token bucket refill rate (tokens/second) for new API clients |
| `RUST_LOG` | no | `happyview=debug,tower_http=debug` | Log filter (uses `tracing_subscriber::EnvFilter`) |
| `APP_NAME` | no | --- | Application name shown on OAuth authorization screens. Overridden by database setting if set via admin API |
| `LOGO_URI` | no | --- | URL to application logo for OAuth screens. Overridden by database setting or logo upload |
| `TOS_URI` | no | --- | URL to terms of service. Overridden by database setting if set via admin API |
| `POLICY_URI` | no | --- | URL to privacy policy. Overridden by database setting if set via admin API |

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
# JETSTREAM_URL=wss://jetstream1.us-east.bsky.network
# RELAY_URL=https://bsky.network
# PLC_URL=https://plc.directory
# STATIC_DIR=./web/out
# EVENT_LOG_RETENTION_DAYS=30
# TOKEN_ENCRYPTION_KEY=base64-encoded-32-byte-key
# DEFAULT_RATE_LIMIT_CAPACITY=100
# DEFAULT_RATE_LIMIT_REFILL_RATE=2.0
# RUST_LOG=happyview=debug,tower_http=debug
# APP_NAME=My App
# LOGO_URI=https://example.com/logo.png
# TOS_URI=https://example.com/tos
# POLICY_URI=https://example.com/privacy
```

## Next steps

- [Authentication](authentication.md) — set up OAuth and admin users
- [Dashboard](dashboard.md) — explore the admin dashboard
- [Production deployment](../reference/production-deployment.md) — deploy HappyView to production
