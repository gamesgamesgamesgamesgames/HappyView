# Admin API: Script Variables

Script variables are encrypted key/value pairs available to Lua scripts via the `vars` global. Use them for secrets like API tokens.

```sh
# All examples assume $TOKEN is an API key (hv_...)
AUTH="Authorization: Bearer $TOKEN"
```

## List script variables

```
GET /admin/script-variables
```

Requires `script-variables:read`. Returns a list of variable keys (values are not returned).

## Upsert a script variable

```
POST /admin/script-variables
```

Requires `script-variables:create`.

```sh
curl -X POST http://127.0.0.1:3000/admin/script-variables \
  -H "$AUTH" \
  -H "Content-Type: application/json" \
  -d '{ "key": "ALGOLIA_API_KEY", "value": "..." }'
```

The value is encrypted at rest using `TOKEN_ENCRYPTION_KEY`.

## Delete a script variable

```
DELETE /admin/script-variables/{key}
```

Requires `script-variables:delete`.
