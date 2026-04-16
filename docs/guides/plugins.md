# Plugins

HappyView uses WASM plugins to integrate with external platforms. Auth plugins enable users to link their accounts from platforms like Steam, Xbox, itch.io, and others, then sync data (like game libraries) to their AT Protocol identity.

Official plugins for Steam, Xbox, itch.io, and other platforms are available in the [happyview-plugins](https://github.com/gamesgamesgamesgames/happyview-plugins) repository.

## Installing Plugins

### Via Dashboard

1. Go to **Settings > Plugins**
2. Click **Add Plugin**
3. Enter the URL to a plugin's `manifest.json` or `.wasm` file
4. Review the plugin details and click **Install Plugin**
5. Configure any required secrets using the settings button

### Via Environment Variables

Set `PLUGIN_URLS` to load plugins at startup:

```
PLUGIN_URLS=steam|https://example.com/plugins/steam/manifest.json
```

Format: `id|url` or `id|url|sha256:hash` (comma-separated for multiple).

### Via File System

Place plugins in the `./plugins/` directory:

```
plugins/
  steam/
    manifest.json
    plugin.wasm
```

## Plugin Configuration

Plugins may require secrets (API keys, client credentials, etc.) to function. There are two ways to configure these:

### Dashboard Configuration

Click the settings icon next to a plugin to enter secrets. These are encrypted using AES-256-GCM and stored in the database.

**Requires:** `TOKEN_ENCRYPTION_KEY` environment variable (base64-encoded 32-byte key).

Generate one with:
```bash
openssl rand -base64 32
```

### Environment Variables

Set secrets as environment variables with the `PLUGIN_<ID>_` prefix:

```bash
PLUGIN_STEAM_API_KEY=your-api-key
PLUGIN_XBOX_CLIENT_ID=your-client-id
PLUGIN_XBOX_CLIENT_SECRET=your-client-secret
```

Dashboard-configured secrets take precedence over environment variables.

## Plugin Manifest

Each plugin has a `manifest.json` that describes its metadata:

```json
{
  "id": "steam",
  "name": "Steam",
  "version": "1.0.0",
  "api_version": "1",
  "description": "Import your Steam game library and playtime data.",
  "icon_url": "https://example.com/steam-icon.png",
  "auth_type": "openid",
  "wasm_file": "steam.wasm",
  "required_secrets": [
    {
      "key": "PLUGIN_STEAM_API_KEY",
      "name": "Steam Web API Key",
      "description": "Get your API key at steamcommunity.com/dev/apikey"
    }
  ]
}
```

| Field | Description |
|-------|-------------|
| `id` | Unique plugin identifier |
| `name` | Display name |
| `version` | Semantic version |
| `api_version` | Plugin API version (currently "1") |
| `description` | Brief description shown during install |
| `icon_url` | Optional icon URL |
| `auth_type` | Authentication type: `oauth2`, `openid`, or `api_key` |
| `wasm_file` | WASM binary filename (default: `plugin.wasm`) |
| `required_secrets` | Array of secrets the plugin needs |

## API Endpoints

### Public Endpoints

| Endpoint | Description |
|----------|-------------|
| `GET /external-auth/providers` | List available auth providers |
| `GET /external-auth/accounts` | List user's linked accounts |
| `GET /external-auth/{plugin}/authorize` | Start OAuth flow |
| `GET /external-auth/{plugin}/callback` | OAuth callback handler |
| `POST /external-auth/{plugin}/sync` | Sync data from linked account |
| `POST /external-auth/{plugin}/unlink` | Unlink account |
| `POST /external-auth/{plugin}/connect` | Connect with API key (for `api_key` auth type) |

### Admin Endpoints

| Endpoint | Description |
|----------|-------------|
| `GET /admin/plugins` | List installed plugins |
| `POST /admin/plugins` | Install a plugin |
| `POST /admin/plugins/preview` | Preview plugin before installing |
| `GET /admin/plugins/official` | Browse the official plugin registry catalog |
| `DELETE /admin/plugins/{id}` | Remove a plugin |
| `POST /admin/plugins/{id}/reload` | Reload plugin from source |
| `POST /admin/plugins/{id}/check-update` | Check whether a newer version is available |
| `GET /admin/plugins/{id}/secrets` | Get configured secrets (masked) |
| `PUT /admin/plugins/{id}/secrets` | Update plugin secrets |

The dashboard's **Settings > Plugins** page calls `GET /admin/plugins/official` to populate the install browser, and `POST /admin/plugins/{id}/check-update` to display update badges on installed plugins.

## Security

- **Sandboxed execution**: Plugins run in isolated WASM environments
- **Limited host access**: Plugins can only call approved host functions (HTTP requests, KV storage, secrets, logging)
- **Encrypted storage**: OAuth tokens and secrets are encrypted at rest using AES-256-GCM
- **Scoped storage**: Plugin KV storage is isolated per-plugin and per-user
- **No filesystem access**: Plugins cannot access the host filesystem

## Developing Plugins

See the [happyview-plugins](https://github.com/gamesgamesgamesgames/happyview-plugins) repository for examples and the plugin SDK.

### Plugin Exports

Plugins must export these functions:

| Export | Signature | Description |
|--------|-----------|-------------|
| `alloc` | `(size: u32) -> u32` | Allocate memory |
| `dealloc` | `(ptr: u32, size: u32)` | Deallocate memory |
| `get_authorize_url` | `(ptr: u32, len: u32) -> i64` | Generate OAuth authorize URL |
| `handle_callback` | `(ptr: u32, len: u32) -> i64` | Handle OAuth callback |
| `refresh_tokens` | `(ptr: u32, len: u32) -> i64` | Refresh expired tokens |
| `get_profile` | `(ptr: u32, len: u32) -> i64` | Get external profile info |
| `sync_account` | `(ptr: u32, len: u32) -> i64` | Sync data and return records |

### Host Functions

Plugins can import these host functions:

| Import | Description |
|--------|-------------|
| `host_http_request` | Make HTTP requests |
| `host_get_secret` | Read configured secrets |
| `host_log` | Write to server logs |
| `host_kv_get` | Read from KV storage |
| `host_kv_set` | Write to KV storage |
| `host_kv_delete` | Delete from KV storage |

## Next steps

- [Official plugins repository](https://github.com/gamesgamesgamesgames/happyview-plugins) — ready-to-use plugins for Steam, Xbox, itch.io, and more
- [API Keys](api-keys.md) — authenticate programmatic access to admin endpoints
- [Permissions](permissions.md) — configure user access to plugin management
