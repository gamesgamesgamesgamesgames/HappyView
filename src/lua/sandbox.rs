use mlua::{Lua, LuaSerdeExt, Result as LuaResult};

use super::tid::generate_tid;

const INSTRUCTION_LIMIT: u32 = 1_000_000;

/// Create a fresh sandboxed Lua VM.
///
/// - Dangerous globals (`os`, `io`, `debug`, `package`, `require`, `dofile`, `loadfile`, `load`) are removed.
/// - An instruction-count hook prevents infinite loops.
/// - Utility globals `now()` and `log()` are injected.
pub fn create_sandbox() -> LuaResult<Lua> {
    let lua = Lua::new();

    // Remove dangerous globals
    let globals = lua.globals();
    for name in &[
        "os",
        "io",
        "debug",
        "package",
        "require",
        "dofile",
        "loadfile",
        "load",
        "collectgarbage",
    ] {
        globals.raw_set(*name, mlua::Value::Nil)?;
    }

    // Instruction limit to prevent infinite loops
    lua.set_hook(
        mlua::HookTriggers::new().every_nth_instruction(INSTRUCTION_LIMIT),
        |_lua, _debug| Err(mlua::Error::runtime("script exceeded execution limit")),
    )?;

    // Utility: now() returns UTC ISO 8601 string
    let now_fn = lua.create_function(|_, ()| Ok(chrono::Utc::now().to_rfc3339()))?;
    globals.set("now", now_fn)?;

    // Utility: log(message) logs via tracing::debug
    let log_fn = lua.create_function(|_, msg: String| {
        tracing::debug!(lua_log = %msg, "lua script log");
        Ok(())
    })?;
    globals.set("log", log_fn)?;

    // Utility: TID() returns a fresh AT Protocol TID string
    let tid_fn = lua.create_function(|_, ()| Ok(generate_tid()))?;
    globals.set("TID", tid_fn)?;

    // Utility: toarray(table) marks a table as a JSON array for serialization.
    // Ensures empty tables serialize as [] instead of {}.
    let toarray_fn = lua.create_function(|lua, table: mlua::Table| {
        let values: Vec<mlua::Value> = table.sequence_values().collect::<LuaResult<_>>()?;
        let seq = lua.create_sequence_from(values)?;
        seq.set_metatable(Some(lua.array_metatable()))?;
        Ok(seq)
    })?;
    globals.set("toarray", toarray_fn)?;

    Ok(lua)
}

/// Validate that a script compiles and defines a `handle` function.
pub fn validate_script(source: &str) -> Result<(), String> {
    let lua = create_sandbox().map_err(|e| format!("failed to create Lua VM: {e}"))?;
    lua.load(source)
        .exec()
        .map_err(|e| format!("script compilation failed: {e}"))?;

    let globals = lua.globals();
    match globals.get::<mlua::Function>("handle") {
        Ok(_) => Ok(()),
        Err(_) => Err("script must define a handle() function".into()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sandbox_removes_dangerous_globals() {
        let lua = create_sandbox().unwrap();
        let globals = lua.globals();
        assert!(globals.get::<mlua::Value>("os").unwrap().is_nil());
        assert!(globals.get::<mlua::Value>("io").unwrap().is_nil());
        assert!(globals.get::<mlua::Value>("debug").unwrap().is_nil());
        assert!(globals.get::<mlua::Value>("package").unwrap().is_nil());
        assert!(globals.get::<mlua::Value>("require").unwrap().is_nil());
    }

    #[test]
    fn sandbox_provides_now() {
        let lua = create_sandbox().unwrap();
        let result: String = lua.load("return now()").eval().unwrap();
        assert!(result.contains("T")); // ISO 8601 format
    }

    #[test]
    fn sandbox_provides_log() {
        let lua = create_sandbox().unwrap();
        lua.load(r#"log("test message")"#).exec().unwrap();
    }

    #[test]
    fn sandbox_provides_tid() {
        let lua = create_sandbox().unwrap();
        let result: String = lua.load("return TID()").eval().unwrap();
        assert_eq!(result.len(), 13);
        let valid = "234567abcdefghijklmnopqrstuvwxyz";
        for ch in result.chars() {
            assert!(valid.contains(ch), "invalid char '{ch}' in TID");
        }
    }

    #[test]
    fn sandbox_tid_returns_unique_values() {
        let lua = create_sandbox().unwrap();
        let a: String = lua.load("return TID()").eval().unwrap();
        let b: String = lua.load("return TID()").eval().unwrap();
        assert_ne!(a, b);
    }

    #[test]
    fn sandbox_kills_infinite_loop() {
        let lua = create_sandbox().unwrap();
        let result = lua.load("while true do end").exec();
        assert!(result.is_err());
        let err = result.unwrap_err().to_string();
        assert!(
            err.contains("execution limit"),
            "expected execution limit error, got: {err}"
        );
    }

    #[test]
    fn validate_script_accepts_valid() {
        let result = validate_script("function handle() return {} end");
        assert!(result.is_ok());
    }

    #[test]
    fn validate_script_rejects_missing_handle() {
        let result = validate_script("function other() return {} end");
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("handle"));
    }

    #[test]
    fn validate_script_rejects_syntax_error() {
        let result = validate_script("function handle(");
        assert!(result.is_err());
    }

    #[test]
    fn sandbox_provides_toarray() {
        let lua = create_sandbox().unwrap();
        lua.load(r#"result = toarray({})"#).exec().unwrap();
    }

    #[test]
    fn sandbox_toarray_preserves_values() {
        let lua = create_sandbox().unwrap();
        let result: Vec<i64> = lua
            .load(r#"return toarray({10, 20, 30})"#)
            .eval::<mlua::Table>()
            .unwrap()
            .sequence_values()
            .collect::<LuaResult<_>>()
            .unwrap();
        assert_eq!(result, vec![10, 20, 30]);
    }

    #[test]
    fn sandbox_toarray_empty_serializes_as_array() {
        use mlua::LuaSerdeExt;
        let lua = create_sandbox().unwrap();
        let table: mlua::Table = lua.load(r#"return toarray({})"#).eval().unwrap();
        let json: serde_json::Value = lua.from_value(mlua::Value::Table(table)).unwrap();
        assert!(json.is_array(), "expected JSON array, got: {json}");
    }
}
