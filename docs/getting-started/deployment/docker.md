# Local Development with Docker

This guide runs the full HappyView stack locally using Docker Compose: [Tap](https://github.com/bluesky-social/indigo/tree/main/cmd/tap), HappyView, and the web dashboard.

## Prerequisites

- [Docker](https://docs.docker.com/get-docker/) and Docker Compose

## 1. Clone and configure

```sh
git clone https://github.com/graze-social/happyview.git
cd happyview
cp .env.example .env
```

Set `TAP_ADMIN_PASSWORD` in your `.env`. This shared secret is used by both Tap and HappyView:

```sh
TAP_ADMIN_PASSWORD=your-secret-here
```

The `docker-compose.yml` configures everything else (service connections) automatically. See the [database setup guide](../../guides/database-setup.md) if you want to use Postgres instead.

## 2. Start the stack

```sh
docker compose up
```

This starts:

| Service       | Port | Description                        |
| ------------- | ---- | ---------------------------------- |
| **tap**       | 2480 | Firehose consumer, backfill worker |
| **happyview** | 3000 | HappyView API server               |
| **web**       | 3001 | Next.js dashboard                  |

HappyView runs migrations automatically on startup. The first build will take a few minutes while Rust compiles.

:::tip
To use Postgres instead of SQLite, uncomment the `postgres` service in `docker-compose.yml` and update `DATABASE_URL` in `.env`. See the [database setup guide](../../guides/database-setup.md).
:::

## Next steps

Your HappyView stack is running. Follow the [Statusphere tutorial](../../tutorials/statusphere.md) to upload lexicons, add custom query logic, and start indexing records from the network.
