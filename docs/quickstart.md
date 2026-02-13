# Quickstart

## Prerequisites

- Rust (stable)
- PostgreSQL 17+
- A running [AIP](https://github.com/graze-social/aip) instance

## 1. Clone and configure

```sh
git clone https://github.com/graze-social/happyview.git
cd happyview
cp .env.example .env
```

Edit `.env`:

```sh
DATABASE_URL=postgres://happyview:happyview@localhost/happyview
AIP_URL=http://localhost:8080
```

See [Configuration](configuration.md) for all available variables.

## 2. Start Postgres and run migrations

```sh
docker compose up -d postgres
cargo run
```

Migrations run automatically on startup.

## 3. Upload a lexicon

The first authenticated request to an admin endpoint auto-creates you as the initial admin. Authenticate with an AIP-issued Bearer token:

```sh
curl -X POST http://localhost:3000/admin/lexicons \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "lexicon_json": {
      "lexicon": 1,
      "id": "games.gamesgamesgamesgames.game",
      "defs": {
        "main": {
          "type": "record",
          "key": "tid",
          "record": {
            "type": "object",
            "properties": {
              "title": { "type": "string" }
            }
          }
        }
      }
    },
    "backfill": true
  }'
```

HappyView now subscribes to `games.gamesgamesgamesgames.game` on Jetstream and starts indexing records.

## 4. Query records

```sh
curl http://localhost:3000/xrpc/games.gamesgamesgamesgames.listGames?limit=10
```

See [XRPC API](xrpc-api.md) for query and procedure details.
