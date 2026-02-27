# Local Development from Source

This guide runs HappyView directly with `cargo run`, with you managing Postgres, AIP, and Tap separately. If you'd rather use Docker Compose to run everything together, see [Local Development with Docker](docker.md).

## Prerequisites

- Rust (stable)
- PostgreSQL 17+
- A running [AIP](https://github.com/graze-social/aip) instance (handles OAuth). See the [AIP documentation](https://github.com/graze-social/aip) for setup.
- A running [Tap](https://github.com/bluesky-social/indigo/tree/main/cmd/tap) instance (delivers real-time records and handles backfill). See the [Tap documentation](https://github.com/bluesky-social/indigo/tree/main/cmd/tap) for setup.

## 1. Clone and configure

```sh
git clone https://github.com/graze-social/happyview.git
cd happyview
cp .env.example .env
```

Edit `.env` to point at your running services:

```sh
DATABASE_URL=postgres://happyview:happyview@localhost/happyview
AIP_URL=http://localhost:8080
TAP_URL=http://localhost:2480
TAP_ADMIN_PASSWORD=your-secret-here
```

See [Configuration](../configuration.md) for all available variables.

## 2. Create the database

```sh
createdb happyview
```

Or if using a Postgres user with a password:

```sh
psql -c "CREATE DATABASE happyview;" -U postgres
```

HappyView runs migrations automatically on startup, so no manual migration step is needed.

## 3. Start HappyView

```sh
cargo run
```

HappyView starts on port 3000 (configurable via the `PORT` environment variable).

## Next steps

Your HappyView instance is running. Follow the [Statusphere tutorial](../../tutorials/statusphere.md) to upload lexicons, add custom query logic, and start indexing records from the network.
