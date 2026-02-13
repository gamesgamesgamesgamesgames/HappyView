# Configuration

HappyView is configured via environment variables. A `.env` file in the project root is loaded automatically on startup.

## Environment variables

| Variable | Required | Default | Description |
|----------|----------|---------|-------------|
| `DATABASE_URL` | yes | --- | Postgres connection string |
| `AIP_URL` | yes | --- | AIP instance URL for OAuth token validation |
| `HOST` | no | `0.0.0.0` | Bind host |
| `PORT` | no | `3000` | Bind port |
| `JETSTREAM_URL` | no | `wss://jetstream2.us-west.bsky.network/subscribe` | Jetstream WebSocket URL |
| `RELAY_URL` | no | `https://bsky.network` | Relay URL for backfill repo discovery |
| `PLC_URL` | no | `https://plc.directory` | PLC directory URL for DID resolution |
| `RUST_LOG` | no | `happyview=debug,tower_http=debug` | Log filter (uses `tracing_subscriber::EnvFilter`) |

## Example `.env`

```sh
DATABASE_URL=postgres://happyview:happyview@localhost/happyview
AIP_URL=http://localhost:8080

# Optional overrides
# HOST=0.0.0.0
# PORT=3000
# JETSTREAM_URL=wss://jetstream2.us-west.bsky.network/subscribe
# RELAY_URL=https://bsky.network
# PLC_URL=https://plc.directory
# RUST_LOG=happyview=debug,tower_http=debug
```
