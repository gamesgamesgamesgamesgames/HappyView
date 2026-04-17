# Local Development with Docker

This guide runs HappyView and the dashboard locally using Docker Compose.

## Prerequisites

- [Docker](https://docs.docker.com/get-docker/) and Docker Compose

## 1. Clone and configure

```sh
git clone https://github.com/graze-social/happyview.git
cd happyview
cp .env.example .env
```

Edit `.env` and set at least `PUBLIC_URL` (e.g. `http://localhost:3000`) and `SESSION_SECRET`. The defaults work for everything else. See [Configuration](../configuration.md) for the full list of environment variables.

## 2. Start the stack

```sh
docker compose up
```

This starts:

| Service       | Port | Description           |
| ------------- | ---- | --------------------- |
| **happyview** | 3000 | HappyView API server  |
| **web**       | 3001 | Next.js dashboard     |

HappyView runs migrations automatically on startup. The first build will take a few minutes while Rust compiles.

The `happyview` container serves its own bundled dashboard at `http://localhost:3000`, but that copy is baked in at container build time and only updates when you rebuild the image. For day-to-day development, use the dev dashboard at `http://localhost:3001` — it hot-reloads on changes to the `web/` source.

:::tip
SQLite is the default and requires no extra services. To use Postgres instead, uncomment the `postgres` service in `docker-compose.yml` and update `DATABASE_URL` in `.env`. See the [database setup guide](../../guides/database-setup.md).
:::

## Next steps

Your HappyView stack is running. Follow the [Statusphere tutorial](../../tutorials/statusphere.md) to upload lexicons, add custom query logic, and start indexing records from the network.
