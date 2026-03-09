use mlua::{Lua, LuaSerdeExt, Result as LuaResult};
use serde_json::Value;
use std::collections::HashMap;

/// Set global context variables for a procedure script.
pub fn set_procedure_context(
    lua: &Lua,
    method: &str,
    input: &Value,
    caller_did: &str,
    collection: &str,
) -> LuaResult<()> {
    let globals = lua.globals();
    globals.set("method", method.to_string())?;
    globals.set("input", lua.to_value(input)?)?;
    globals.set("caller_did", caller_did.to_string())?;
    globals.set("collection", collection.to_string())?;
    Ok(())
}

/// Set global context variables for a query script.
pub fn set_query_context(
    lua: &Lua,
    method: &str,
    params: &HashMap<String, Value>,
    collection: &str,
) -> LuaResult<()> {
    let globals = lua.globals();
    globals.set("method", method.to_string())?;
    globals.set("params", lua.to_value(params)?)?;
    globals.set("collection", collection.to_string())?;
    Ok(())
}

/// Set the `env` global table from script variables.
pub fn set_env_context(lua: &Lua, vars: &HashMap<String, String>) -> LuaResult<()> {
    let globals = lua.globals();
    globals.set("env", lua.to_value(vars)?)?;
    Ok(())
}

/// Set global context variables for an index hook script.
pub fn set_hook_context(
    lua: &Lua,
    action: &str,
    uri: &str,
    did: &str,
    collection: &str,
    rkey: &str,
    record: Option<&Value>,
) -> LuaResult<()> {
    let globals = lua.globals();
    globals.set("action", action.to_string())?;
    globals.set("uri", uri.to_string())?;
    globals.set("did", did.to_string())?;
    globals.set("collection", collection.to_string())?;
    globals.set("rkey", rkey.to_string())?;
    match record {
        Some(r) => globals.set("record", lua.to_value(r)?)?,
        None => globals.set("record", mlua::Value::Nil)?,
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::lua::sandbox::create_sandbox;
    use serde_json::json;

    #[test]
    fn hook_context_sets_all_globals() {
        let lua = create_sandbox().unwrap();
        let record = json!({"name": "Test Game"});
        set_hook_context(
            &lua,
            "create",
            "at://did:plc:abc/col/rkey",
            "did:plc:abc",
            "col",
            "rkey",
            Some(&record),
        )
        .unwrap();

        let globals = lua.globals();
        assert_eq!(globals.get::<String>("action").unwrap(), "create");
        assert_eq!(
            globals.get::<String>("uri").unwrap(),
            "at://did:plc:abc/col/rkey"
        );
        assert_eq!(globals.get::<String>("did").unwrap(), "did:plc:abc");
        assert_eq!(globals.get::<String>("collection").unwrap(), "col");
        assert_eq!(globals.get::<String>("rkey").unwrap(), "rkey");

        let rec: mlua::Table = globals.get("record").unwrap();
        assert_eq!(rec.get::<String>("name").unwrap(), "Test Game");
    }

    #[test]
    fn procedure_context_sets_all_globals() {
        let lua = create_sandbox().unwrap();
        let input = json!({"key": "val"});
        set_procedure_context(
            &lua,
            "com.example.doThing",
            &input,
            "did:plc:test",
            "com.example.thing",
        )
        .unwrap();

        let globals = lua.globals();
        assert_eq!(
            globals.get::<String>("method").unwrap(),
            "com.example.doThing"
        );
        assert_eq!(globals.get::<String>("caller_did").unwrap(), "did:plc:test");
        assert_eq!(
            globals.get::<String>("collection").unwrap(),
            "com.example.thing"
        );

        let input_table: mlua::Table = globals.get("input").unwrap();
        assert_eq!(input_table.get::<String>("key").unwrap(), "val");
    }

    #[test]
    fn query_context_sets_all_globals() {
        let lua = create_sandbox().unwrap();
        let mut params = HashMap::new();
        params.insert("limit".to_string(), json!("10"));
        params.insert("cursor".to_string(), json!("abc"));
        set_query_context(&lua, "com.example.listThings", &params, "com.example.thing").unwrap();

        let globals = lua.globals();
        assert_eq!(
            globals.get::<String>("method").unwrap(),
            "com.example.listThings"
        );
        assert_eq!(
            globals.get::<String>("collection").unwrap(),
            "com.example.thing"
        );

        let params_table: mlua::Table = globals.get("params").unwrap();
        assert_eq!(params_table.get::<String>("limit").unwrap(), "10");
        assert_eq!(params_table.get::<String>("cursor").unwrap(), "abc");
    }

    #[test]
    fn env_context_sets_table() {
        let lua = create_sandbox().unwrap();
        let mut vars = HashMap::new();
        vars.insert("API_KEY".to_string(), "secret123".to_string());
        vars.insert("OTHER".to_string(), "value".to_string());
        set_env_context(&lua, &vars).unwrap();

        let globals = lua.globals();
        let env: mlua::Table = globals.get("env").unwrap();
        assert_eq!(env.get::<String>("API_KEY").unwrap(), "secret123");
        assert_eq!(env.get::<String>("OTHER").unwrap(), "value");
    }

    #[test]
    fn env_context_empty_map() {
        let lua = create_sandbox().unwrap();
        let vars = HashMap::new();
        set_env_context(&lua, &vars).unwrap();

        let globals = lua.globals();
        let env: mlua::Table = globals.get("env").unwrap();
        assert!(env.get::<mlua::Value>("anything").unwrap().is_nil());
    }

    #[test]
    fn hook_context_record_nil_on_delete() {
        let lua = create_sandbox().unwrap();
        set_hook_context(
            &lua,
            "delete",
            "at://did:plc:abc/col/rkey",
            "did:plc:abc",
            "col",
            "rkey",
            None,
        )
        .unwrap();

        let globals = lua.globals();
        assert_eq!(globals.get::<String>("action").unwrap(), "delete");
        assert!(globals.get::<mlua::Value>("record").unwrap().is_nil());
    }
}
