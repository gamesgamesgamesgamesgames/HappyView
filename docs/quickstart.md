# Quickstart

## Deploy on Railway

The fastest way to get HappyView running is with Railway. This template deploys HappyView, AIP, Tap, and Postgres with a single click:

[![Deploy on Railway](https://railway.com/button.svg)](https://railway.com/deploy/I1jvZl?referralCode=0QOgj_)

### Required configuration

After deploying the template, you'll need to configure a few things before the stack works properly:

1. **Set your admin DID.** In the AIP service variables, set `ADMIN_DIDS` to your AT Protocol DID (e.g. `did:plc:abc123...`). You can find your DID by looking up your handle on [Internect](https://internect.info/).

2. **Generate AIP signing keys.** The `OAUTH_SIGNING_KEYS` and `ATPROTO_OAUTH_SIGNING_KEYS` variables require multibase-encoded P-256 private keys. See the [AIP Signing Keys documentation](https://github.com/graze-social/aip/blob/main/CONFIGURATION.md#signing-keys) for generation instructions.

3. **Generate public URLs.** The services won't work until HappyView and AIP have public domains assigned in Railway.

## Local development

### Prerequisites

- Rust (stable)
- PostgreSQL 17+
- A running [AIP](https://github.com/graze-social/aip) instance

### 1. Clone and configure

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

### 2. Start Postgres and run migrations

```sh
docker compose up -d postgres
cargo run
```

Migrations run automatically on startup.

### 3. Upload a lexicon

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

### 4. Query records

```sh
curl http://localhost:3000/xrpc/games.gamesgamesgamesgames.listGames?limit=10
```

See [XRPC API](xrpc-api.md) for query and procedure details.
