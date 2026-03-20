# HappyView Plugin System

HappyView supports WASM plugins for extending functionality. The first plugin type is external auth providers (Steam, GOG, Epic, etc.).

## Configuration

### Environment Variables

- `TOKEN_ENCRYPTION_KEY`: Base64-encoded 32-byte key for encrypting OAuth tokens (required for external auth)
- `PLUGIN_URLS`: Comma-separated list of plugins to load from URLs

### PLUGIN_URLS Format

```
id|url|sha256:hash,id|url|sha256:hash
```

Example:
```
PLUGIN_URLS=steam|https://github.com/org/plugins/releases/download/v1.0.0/steam.wasm|sha256:abc123
```

### File-based Plugins

Place plugins in the `./plugins/` directory:

```
plugins/
  steam/
    plugin.wasm
    plugin.toml
```

## API Endpoints

- `GET /external-auth/providers` - List available auth providers
- `GET /external-auth/{plugin_id}/authorize?redirect_uri=...` - Start auth flow
- `GET /external-auth/{plugin_id}/callback` - OAuth callback
- `POST /external-auth/{plugin_id}/sync` - Sync account data
- `POST /external-auth/{plugin_id}/unlink` - Unlink account

## Plugin Development

See the [Plugin Development Guide](./plugin-development.md) for creating custom plugins.

## Security

- OAuth tokens are encrypted at rest using AES-256-GCM
- Plugins run in a sandboxed WASM environment
- Plugins can only access host functions (HTTP, KV, secrets, logging)
- KV storage is scoped per-plugin and per-user
