# Developing Plugins

This guide covers how to build your own HappyView WASM plugins. For installing and configuring plugins, see the [Plugins guide](plugins.md).

See the [happyview-plugins](https://tangled.org/gamesgamesgamesgames.games/happyview-plugins) repository for examples and the plugin SDK.

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

| Field              | Description                                           |
| ------------------ | ----------------------------------------------------- |
| `id`               | Unique plugin identifier                              |
| `name`             | Display name                                          |
| `version`          | Semantic version                                      |
| `api_version`      | Plugin API version (currently "1")                    |
| `description`      | Brief description shown during install                |
| `icon_url`         | Optional icon URL                                     |
| `auth_type`        | Authentication type: `oauth2`, `openid`, or `api_key` |
| `wasm_file`        | WASM binary filename (default: `plugin.wasm`)         |
| `required_secrets` | Array of secrets the plugin needs                     |

## API Endpoints

### Public Endpoints

| Endpoint                                | Description                                    |
| --------------------------------------- | ---------------------------------------------- |
| `GET /external-auth/providers`          | List available auth providers                  |
| `GET /external-auth/accounts`           | List user's linked accounts                    |
| `GET /external-auth/{plugin}/authorize` | Start OAuth flow                               |
| `GET /external-auth/{plugin}/callback`  | OAuth callback handler                         |
| `POST /external-auth/{plugin}/sync`     | Sync data from linked account                  |
| `POST /external-auth/{plugin}/unlink`   | Unlink account                                 |
| `POST /external-auth/{plugin}/connect`  | Connect with API key (for `api_key` auth type) |

### Admin Endpoints

| Endpoint                                | Description                                 |
| --------------------------------------- | ------------------------------------------- |
| `GET /admin/plugins`                    | List installed plugins                      |
| `POST /admin/plugins`                   | Install a plugin                            |
| `POST /admin/plugins/preview`           | Preview plugin before installing            |
| `GET /admin/plugins/official`           | Browse the official plugin registry catalog |
| `DELETE /admin/plugins/{id}`            | Remove a plugin                             |
| `POST /admin/plugins/{id}/reload`       | Reload plugin from source                   |
| `POST /admin/plugins/{id}/check-update` | Check whether a newer version is available  |
| `GET /admin/plugins/{id}/secrets`       | Get configured secrets (masked)             |
| `PUT /admin/plugins/{id}/secrets`       | Update plugin secrets                       |

The dashboard's **Settings > Plugins** page calls `GET /admin/plugins/official` to populate the install browser, and `POST /admin/plugins/{id}/check-update` to display update badges on installed plugins.

## Plugin Exports

Plugins must export these functions:

| Export              | Signature                     | Description                  |
| ------------------- | ----------------------------- | ---------------------------- |
| `alloc`             | `(size: u32) -> u32`          | Allocate memory              |
| `dealloc`           | `(ptr: u32, size: u32)`       | Deallocate memory            |
| `get_authorize_url` | `(ptr: u32, len: u32) -> i64` | Generate OAuth authorize URL |
| `handle_callback`   | `(ptr: u32, len: u32) -> i64` | Handle OAuth callback        |
| `refresh_tokens`    | `(ptr: u32, len: u32) -> i64` | Refresh expired tokens       |
| `get_profile`       | `(ptr: u32, len: u32) -> i64` | Get external profile info    |
| `sync_account`      | `(ptr: u32, len: u32) -> i64` | Sync data and return records |

## Host Functions

Plugins can import these host functions:

| Import              | Description             |
| ------------------- | ----------------------- |
| `host_http_request` | Make HTTP requests      |
| `host_get_secret`   | Read configured secrets |
| `host_log`          | Write to server logs    |
| `host_kv_get`       | Read from KV storage    |
| `host_kv_set`       | Write to KV storage     |
| `host_kv_delete`    | Delete from KV storage  |

## Next steps

- [Official plugins repository](https://tangled.org/gamesgamesgamesgames.games/happyview-plugins) — ready-to-use plugins and the plugin SDK
- [Plugins guide](plugins.md) — install and configure plugins
- [API Keys](../admin/api-keys.md) — authenticate programmatic access to admin endpoints
- [Permissions](../admin/permissions.md) — configure user access to plugin management
