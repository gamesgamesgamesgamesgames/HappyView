# JSON API

The `json` global provides JSON serialization and deserialization. Available in queries, procedures, and [index hooks](../../guides/index-hooks.md).

## json.encode

```lua
local str = json.encode({ key = "value", items = { 1, 2, 3 } })
-- '{"key":"value","items":[1,2,3]}'
```

Converts a Lua table to a JSON string.

## json.decode

```lua
local tbl = json.decode('{"key": "value"}')
-- tbl.key == "value"
```

Parses a JSON string into a Lua table. Returns an error if the input is not valid JSON.
