# Admin API: Instance Settings

Instance settings override environment variables at runtime — things like app name, ToS URL, privacy policy URL, and logo. Settings stored here take precedence over their env var equivalents. All endpoints require the `settings:manage` permission.

```sh
# All examples assume $TOKEN is an API key (hv_...)
AUTH="Authorization: Bearer $TOKEN"
```

## List settings

```
GET /admin/settings
```

```sh
curl http://localhost:3000/admin/settings -H "$AUTH"
```

Returns all key/value pairs stored in the `instance_settings` table.

## Upsert a setting

```
PUT /admin/settings/{key}
```

```sh
curl -X PUT http://localhost:3000/admin/settings/app_name \
  -H "$AUTH" \
  -H "Content-Type: application/json" \
  -d '{ "value": "My HappyView" }'
```

## Delete a setting

```
DELETE /admin/settings/{key}
```

Removes the override; the corresponding environment variable (if any) takes effect again.

## Upload / delete logo

```
PUT /admin/settings/logo
DELETE /admin/settings/logo
```

`PUT` accepts a binary image body and stores it as the instance logo (served via the public dashboard). `DELETE` removes the stored logo.
