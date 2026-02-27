# Local Development with Docker

This guide runs the full HappyView stack locally using Docker Compose: Postgres, [Tap](https://github.com/bluesky-social/indigo/tree/main/cmd/tap), HappyView, and the web dashboard.

## Prerequisites

- [Docker](https://docs.docker.com/get-docker/) and Docker Compose
- An [AIP](https://github.com/graze-social/aip) instance for OAuth. The Docker Compose config points at the public AIP instance at `aip.gamesgamesgamesgames.games` by default.

:::warning
This public AIP instance is provided for development convenience only. Production deployments should run their own AIP instance or risk being blocked. See the [AIP documentation](https://github.com/graze-social/aip) for setup.
:::

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

The `docker-compose.yml` configures everything else (database URLs, service connections) automatically.

## 2. Start the stack

```sh
docker compose up
```

This starts:

| Service       | Port | Description                                          |
| ------------- | ---- | ---------------------------------------------------- |
| **postgres**  | 5432 | PostgreSQL 17 (databases for both HappyView and Tap) |
| **tap**       | 2480 | Firehose consumer, backfill worker                   |
| **happyview** | 3000 | HappyView API server                                 |
| **web**       | 3001 | Next.js dashboard                                    |

HappyView runs migrations automatically on startup. The first build will take a few minutes while Rust compiles.

## Next steps

Your HappyView stack is running. Follow the [Statusphere tutorial](../../tutorials/statusphere.md) to upload lexicons, add custom query logic, and start indexing records from the network.
