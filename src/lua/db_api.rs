use mlua::{Lua, LuaSerdeExt, Result as LuaResult};
use serde_json::{Value, json};
use sqlx::{Column, Row};
use std::sync::Arc;

use crate::AppState;

/// Register the `db` table with read-only database query functions.
pub fn register_db_api(lua: &Lua, state: Arc<AppState>) -> LuaResult<()> {
    let db_table = lua.create_table()?;

    // db.query({ collection, did?, limit?, offset? }) -> { records, cursor? }
    let state_query = state.clone();
    let query_fn = lua.create_async_function(move |lua, opts: mlua::Table| {
        let state = state_query.clone();
        async move {
            let collection: String = opts.get("collection")?;
            let did: Option<String> = opts.get("did").ok();
            let limit: i64 = opts.get::<i64>("limit").unwrap_or(20).min(100);
            let offset: i64 = opts.get::<i64>("offset").unwrap_or(0);

            let rows: Vec<(String, String, Value)> = if let Some(ref did) = did {
                sqlx::query_as(
                    "SELECT uri, did, record FROM records WHERE collection = $1 AND did = $2 ORDER BY indexed_at DESC LIMIT $3 OFFSET $4",
                )
                .bind(&collection)
                .bind(did)
                .bind(limit)
                .bind(offset)
                .fetch_all(&state.db)
                .await
                .map_err(|e| mlua::Error::runtime(format!("DB query failed: {e}")))?
            } else {
                sqlx::query_as(
                    "SELECT uri, did, record FROM records WHERE collection = $1 ORDER BY indexed_at DESC LIMIT $2 OFFSET $3",
                )
                .bind(&collection)
                .bind(limit)
                .bind(offset)
                .fetch_all(&state.db)
                .await
                .map_err(|e| mlua::Error::runtime(format!("DB query failed: {e}")))?
            };

            let has_next = rows.len() as i64 == limit;
            let records: Vec<Value> = rows
                .into_iter()
                .map(|(uri, _did, mut record)| {
                    if let Some(obj) = record.as_object_mut() {
                        obj.insert("uri".to_string(), json!(uri));
                    }
                    record
                })
                .collect();

            let record_values: Vec<mlua::Value> = records
                .iter()
                .map(|r| lua.to_value(r))
                .collect::<LuaResult<_>>()?;
            let records_table = lua.create_sequence_from(record_values)?;
            records_table.set_metatable(Some(lua.array_metatable()))?;

            let result_table = lua.create_table()?;
            result_table.set("records", records_table)?;
            if has_next {
                let next_cursor = (offset + limit).to_string();
                result_table.set("cursor", next_cursor)?;
            }

            Ok(mlua::Value::Table(result_table))
        }
    })?;
    db_table.set("query", query_fn)?;

    // db.get(uri) -> record table or nil
    let state_get = state.clone();
    let get_fn = lua.create_async_function(move |lua, uri: String| {
        let state = state_get.clone();
        async move {
            let row: Option<(Value,)> = sqlx::query_as("SELECT record FROM records WHERE uri = $1")
                .bind(&uri)
                .fetch_optional(&state.db)
                .await
                .map_err(|e| mlua::Error::runtime(format!("DB query failed: {e}")))?;

            match row {
                Some((mut record,)) => {
                    if let Some(obj) = record.as_object_mut() {
                        obj.insert("uri".to_string(), json!(uri));
                    }
                    lua.to_value(&record)
                }
                None => Ok(mlua::Value::Nil),
            }
        }
    })?;
    db_table.set("get", get_fn)?;

    // db.search({ collection, field, query, limit? }) -> { records }
    let state_search = state.clone();
    let search_fn = lua.create_async_function(move |lua, opts: mlua::Table| {
        let state = state_search.clone();
        async move {
            let collection: String = opts.get("collection")?;
            let field: String = opts.get("field")?;
            let query: String = opts.get("query")?;
            let limit: i64 = opts.get::<i64>("limit").unwrap_or(10).min(100);

            let rows: Vec<(String, String, Value)> = sqlx::query_as(
                "SELECT uri, did, record FROM records \
                 WHERE collection = $1 \
                   AND record->>$2 ILIKE '%' || $3 || '%' \
                 ORDER BY \
                   CASE \
                     WHEN LOWER(record->>$2) = LOWER($3) THEN 0 \
                     WHEN LOWER(record->>$2) LIKE LOWER($3) || '%' THEN 1 \
                     ELSE 2 \
                   END, \
                   record->>$2 \
                 LIMIT $4",
            )
            .bind(&collection)
            .bind(&field)
            .bind(&query)
            .bind(limit)
            .fetch_all(&state.db)
            .await
            .map_err(|e| mlua::Error::runtime(format!("DB search failed: {e}")))?;

            let records: Vec<Value> = rows
                .into_iter()
                .map(|(uri, _did, mut record)| {
                    if let Some(obj) = record.as_object_mut() {
                        obj.insert("uri".to_string(), json!(uri));
                    }
                    record
                })
                .collect();

            let record_values: Vec<mlua::Value> = records
                .iter()
                .map(|r| lua.to_value(r))
                .collect::<LuaResult<_>>()?;
            let records_table = lua.create_sequence_from(record_values)?;
            records_table.set_metatable(Some(lua.array_metatable()))?;

            let result_table = lua.create_table()?;
            result_table.set("records", records_table)?;

            Ok(mlua::Value::Table(result_table))
        }
    })?;
    db_table.set("search", search_fn)?;

    // db.count(collection, did?) -> integer
    let state_count = state.clone();
    let count_fn =
        lua.create_async_function(move |_, (collection, did): (String, Option<String>)| {
            let state = state_count.clone();
            async move {
                let count: (i64,) = if let Some(ref did) = did {
                    sqlx::query_as(
                        "SELECT COUNT(*) FROM records WHERE collection = $1 AND did = $2",
                    )
                    .bind(&collection)
                    .bind(did)
                    .fetch_one(&state.db)
                    .await
                    .map_err(|e| mlua::Error::runtime(format!("DB count failed: {e}")))?
                } else {
                    sqlx::query_as("SELECT COUNT(*) FROM records WHERE collection = $1")
                        .bind(&collection)
                        .fetch_one(&state.db)
                        .await
                        .map_err(|e| mlua::Error::runtime(format!("DB count failed: {e}")))?
                };
                Ok(count.0)
            }
        })?;
    db_table.set("count", count_fn)?;

    // db.raw(sql, params?) -> rows[]
    // Read-only: only SELECT statements are allowed.
    let state_raw = state;
    let raw_fn =
        lua.create_async_function(move |lua, (sql, params): (String, Option<mlua::Table>)| {
            let state = state_raw.clone();
            async move {
                // Only allow SELECT statements
                let trimmed = sql.trim_start().to_uppercase();
                if !trimmed.starts_with("SELECT") {
                    return Err(mlua::Error::runtime("db.raw only supports SELECT queries"));
                }

                // Build query with dynamic parameter binding
                let mut query = sqlx::query(&sql);
                if let Some(ref params_table) = params {
                    for value in params_table.sequence_values::<mlua::Value>() {
                        let value = value?;
                        query = match value {
                            mlua::Value::String(s) => query.bind(s.to_str()?.to_string()),
                            mlua::Value::Integer(n) => query.bind(n),
                            mlua::Value::Number(n) => query.bind(n),
                            mlua::Value::Boolean(b) => query.bind(b),
                            mlua::Value::Nil => query.bind(Option::<String>::None),
                            other => {
                                return Err(mlua::Error::runtime(format!(
                                    "unsupported parameter type: {}",
                                    other.type_name()
                                )));
                            }
                        };
                    }
                }

                let rows = query
                    .fetch_all(&state.db)
                    .await
                    .map_err(|e| mlua::Error::runtime(format!("db.raw query failed: {e}")))?;

                // Convert rows to Lua tables
                let mut lua_rows: Vec<mlua::Value> = Vec::with_capacity(rows.len());
                for row in &rows {
                    let row_table = lua.create_table()?;
                    for col in row.columns() {
                        let name = col.name();
                        let type_name = col.type_info().to_string();
                        let lua_val: mlua::Value = match type_name.as_str() {
                            "TEXT" | "VARCHAR" | "CHAR" | "NAME" | "BPCHAR" => {
                                match row.try_get::<Option<String>, _>(name) {
                                    Ok(Some(s)) => mlua::Value::String(lua.create_string(&s)?),
                                    _ => mlua::Value::Nil,
                                }
                            }
                            "INT4" | "INT2" | "SERIAL" => {
                                match row.try_get::<Option<i32>, _>(name) {
                                    Ok(Some(n)) => mlua::Value::Integer(n as i64),
                                    _ => mlua::Value::Nil,
                                }
                            }
                            "INT8" | "BIGSERIAL" | "BIGINT" => {
                                match row.try_get::<Option<i64>, _>(name) {
                                    Ok(Some(n)) => mlua::Value::Integer(n),
                                    _ => mlua::Value::Nil,
                                }
                            }
                            "FLOAT4" => match row.try_get::<Option<f32>, _>(name) {
                                Ok(Some(n)) => mlua::Value::Number(n as f64),
                                _ => mlua::Value::Nil,
                            },
                            "FLOAT8" | "NUMERIC" => match row.try_get::<Option<f64>, _>(name) {
                                Ok(Some(n)) => mlua::Value::Number(n),
                                _ => mlua::Value::Nil,
                            },
                            "BOOL" => match row.try_get::<Option<bool>, _>(name) {
                                Ok(Some(b)) => mlua::Value::Boolean(b),
                                _ => mlua::Value::Nil,
                            },
                            "JSON" | "JSONB" => match row.try_get::<Option<Value>, _>(name) {
                                Ok(Some(v)) => lua.to_value(&v)?,
                                _ => mlua::Value::Nil,
                            },
                            "TIMESTAMPTZ" | "TIMESTAMP" => {
                                match row.try_get::<Option<chrono::DateTime<chrono::Utc>>, _>(name)
                                {
                                    Ok(Some(dt)) => {
                                        mlua::Value::String(lua.create_string(dt.to_rfc3339())?)
                                    }
                                    _ => mlua::Value::Nil,
                                }
                            }
                            _ => {
                                // Fall back to trying as a string
                                match row.try_get::<Option<String>, _>(name) {
                                    Ok(Some(s)) => mlua::Value::String(lua.create_string(&s)?),
                                    _ => mlua::Value::Nil,
                                }
                            }
                        };
                        row_table.set(name, lua_val)?;
                    }
                    lua_rows.push(mlua::Value::Table(row_table));
                }

                let result = lua.create_sequence_from(lua_rows)?;
                result.set_metatable(Some(lua.array_metatable()))?;
                Ok(result)
            }
        })?;
    db_table.set("raw", raw_fn)?;

    lua.globals().set("db", db_table)?;
    Ok(())
}
