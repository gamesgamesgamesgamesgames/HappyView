use mlua::{Lua, LuaSerdeExt, Result as LuaResult};
use serde_json::{Value, json};
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
    let state_count = state;
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

    lua.globals().set("db", db_table)?;
    Ok(())
}
