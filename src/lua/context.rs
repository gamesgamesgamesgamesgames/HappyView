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
    params: &HashMap<String, String>,
    collection: &str,
) -> LuaResult<()> {
    let globals = lua.globals();
    globals.set("method", method.to_string())?;
    globals.set("params", lua.to_value(params)?)?;
    globals.set("collection", collection.to_string())?;
    Ok(())
}
