# Deployment

## Docker

Build the image:

```sh
docker build -t happyview .
```

### Local development with Docker Compose

```sh
docker compose up
```

This starts Postgres, AIP, and HappyView together. See `docker-compose.yml` for the full configuration.

### Production Compose example

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

## Railway / Fly.io / generic

1. Provision a Postgres database
2. Set `DATABASE_URL` and `AIP_URL` environment variables
3. Deploy the Docker image or build from source
4. HappyView listens on `PORT` (default `3000`)
5. Health check: `GET /health` returns `ok`

## Database

Migrations run automatically on startup via `sqlx::migrate!()`. No manual migration step is needed.

## TLS

HappyView does not terminate TLS. Put it behind a reverse proxy (nginx, Caddy, Cloudflare Tunnel, etc.) for HTTPS.
