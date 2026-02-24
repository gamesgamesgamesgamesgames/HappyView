# Deployment

HappyView requires a Postgres database and an [AIP](https://github.com/graze-social/aip) instance for OAuth. The [Quickstart](../getting-started/deployment/railway) covers the fastest path with Railway. This page covers other deployment options.

## Docker

Build the image:

```sh
docker build -t happyview .
```

For local development, see [Docker deployment](../getting-started/deployment/docker).

### Production Compose example

:::note
This example omits [Tap](https://github.com/bluesky-social/indigo/tree/main/cmd/tap), which is required for real-time record streaming and backfill. See the full `docker-compose.yml` in the repository for a complete configuration including Tap.
:::

```yaml
services:
  postgres:
    image: postgres:17
    environment:
      POSTGRES_USER: happyview
      POSTGRES_PASSWORD: "${POSTGRES_PASSWORD}"
      POSTGRES_DB: happyview
    volumes:
      - pgdata:/var/lib/postgresql/data

  happyview:
    image: happyview:latest
    ports:
      - "3000:3000"
    environment:
      DATABASE_URL: "postgres://happyview:${POSTGRES_PASSWORD}@postgres/happyview"
      AIP_URL: "https://aip.example.com"
    depends_on:
      postgres:
        condition: service_healthy

volumes:
  pgdata:
```

## Railway / Fly.io / other platforms

The general process for any hosting platform:

1. Provision a Postgres 17+ database
2. Deploy an [AIP](https://github.com/graze-social/aip) instance (handles OAuth for your AppView)
3. Set `DATABASE_URL` and `AIP_URL` environment variables (see [Configuration](../getting-started/configuration) for all options)
4. Deploy the Docker image or build from source
5. HappyView listens on `PORT` (default `3000`)
6. Health check: `GET /health` returns `ok`

For Railway specifically, the [Quickstart](../getting-started/deployment/railway) template handles all of this with a single click.

## Database

Migrations run automatically on startup via `sqlx::migrate!()`. No manual migration step is needed.

## TLS

HappyView does not terminate TLS. Put it behind a reverse proxy (nginx, Caddy, Cloudflare Tunnel, etc.) for HTTPS.

## Logging

HappyView uses the `RUST_LOG` environment variable to control log output. The default (`happyview=debug,tower_http=debug`) logs all HappyView activity and HTTP requests. For production, consider `happyview=info,tower_http=info` to reduce noise. See [Configuration](../getting-started/configuration) for details.
