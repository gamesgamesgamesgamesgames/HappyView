# Configuration

HappyView is configured via environment variables. A `.env` file in the project root is loaded automatically on startup. See [Deployment](deployment/docker) for local setup or [Production Deployment](../reference/production-deployment) for production setup.

## Environment variables

| Variable | Required | Default | Description |
|----------|----------|---------|-------------|
| `DATABASE_URL` | yes | --- | Postgres connection string |
| `AIP_URL` | yes | --- | [AIP](https://github.com/graze-social/aip) instance URL for OAuth token validation |
| `HOST` | no | `0.0.0.0` | Bind host |
| `PORT` | no | `3000` | Bind port |
| `TAP_URL` | no | `http://localhost:2480` | [Tap](https://github.com/bluesky-social/indigo/tree/main/cmd/tap) instance URL for real-time record streaming and backfill |
| `TAP_ADMIN_PASSWORD` | no | --- | Shared secret for authenticating with Tap's admin endpoints |
| `RELAY_URL` | no | `https://bsky.network` | Relay URL for [backfill](../guides/backfill) repo discovery |
| `PLC_URL` | no | `https://plc.directory` | [PLC directory](https://github.com/did-method-plc/did-method-plc) URL for DID resolution |
| `RUST_LOG` | no | `happyview=debug,tower_http=debug` | Log filter (uses `tracing_subscriber::EnvFilter`) |

## Example `.env`

```sh
DATABASE_URL=postgres://happyview:happyview@localhost/happyview
AIP_URL=http://localhost:8080

# Optional overrides
# HOST=0.0.0.0
# PORT=3000
# TAP_URL=http://localhost:2480
# TAP_ADMIN_PASSWORD=your-secret-here
# RELAY_URL=https://bsky.network
# PLC_URL=https://plc.directory
# RUST_LOG=happyview=debug,tower_http=debug
```
