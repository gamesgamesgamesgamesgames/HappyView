use futures_util::future::try_join_all;
use mlua::{Lua, LuaSerdeExt, Result as LuaResult};
use serde_json::{Value, json};
use std::sync::Arc;

use crate::AppState;
use crate::auth::Claims;
use crate::repo::{self, AtpSession};

use super::tid::generate_tid;

const INTERNAL_FIELDS: &[&str] = &[
    "_collection",
    "_uri",
    "_cid",
    "_schema",
    "_key_type",
    "_rkey",
];

/// Register the `Record` global constructor and static methods.
/// Only registered for procedure scripts (not queries).
pub fn register_record_api(
    lua: &Lua,
    state: Arc<AppState>,
    claims: Arc<Claims>,
    session: Arc<AtpSession>,
) -> LuaResult<()> {
    // -- methods table (shared by all Record instances) --
    let methods = lua.create_table()?;

    // :save()
    {
        let state = state.clone();
        let claims = claims.clone();
        let session = session.clone();
        let save_fn = lua.create_async_function(move |lua, this: mlua::Table| {
            let state = state.clone();
            let claims = claims.clone();
            let session = session.clone();
            async move {
                let collection: String = this.raw_get("_collection")?;
                let schema: mlua::Value = this.raw_get("_schema")?;

                // Validate required fields against schema
                if let mlua::Value::Table(ref schema_table) = schema {
                    validate_required_fields(&this, schema_table)?;
                }

                // Serialize record data (skip _ keys, inject $type)
                let data = extract_record_data(&lua, &this, &collection)?;

                let existing_uri: Option<String> = this.raw_get("_uri")?;

                let pds_result = if let Some(ref uri) = existing_uri {
                    // PUT
                    let rkey = uri
                        .split('/')
                        .next_back()
                        .ok_or_else(|| mlua::Error::runtime("invalid AT URI"))?
                        .to_string();

                    let pds_body = json!({
                        "repo": claims.did(),
                        "collection": collection,
                        "rkey": rkey,
                        "record": data,
                    });

                    let resp = repo::pds_post_json_raw(
                        &state,
                        &session,
                        "com.atproto.repo.putRecord",
                        &pds_body,
                    )
                    .await
                    .map_err(|e| mlua::Error::runtime(format!("PDS putRecord failed: {e}")))?;

                    if !resp.status().is_success() {
                        let status = resp.status();
                        let body = resp.text().await.unwrap_or_default();
                        return Err(mlua::Error::runtime(format!(
                            "PDS putRecord returned {status}: {body}"
                        )));
                    }

                    let bytes = resp.bytes().await.map_err(|e| {
                        mlua::Error::runtime(format!("failed to read PDS response: {e}"))
                    })?;
                    let result: Value = serde_json::from_slice(&bytes)
                        .map_err(|e| mlua::Error::runtime(format!("invalid PDS JSON: {e}")))?;

                    // Upsert local DB
                    let cid = result
                        .get("cid")
                        .and_then(|v| v.as_str())
                        .unwrap_or_default();
                    let _ = sqlx::query(
                        r#"INSERT INTO records (uri, did, collection, rkey, record, cid)
                           VALUES ($1, $2, $3, $4, $5, $6)
                           ON CONFLICT (uri) DO UPDATE
                               SET record = EXCLUDED.record,
                                   cid = EXCLUDED.cid,
                                   indexed_at = NOW()"#,
                    )
                    .bind(uri)
                    .bind(claims.did())
                    .bind(&collection)
                    .bind(&rkey)
                    .bind(&data)
                    .bind(cid)
                    .execute(&state.db)
                    .await;

                    result
                } else {
                    // CREATE
                    let rkey: Option<String> = this.raw_get("_rkey")?;
                    let mut pds_body = json!({
                        "repo": claims.did(),
                        "collection": collection,
                        "record": data,
                    });
                    if let Some(ref rkey) = rkey {
                        pds_body["rkey"] = json!(rkey);
                    }

                    let resp = repo::pds_post_json_raw(
                        &state,
                        &session,
                        "com.atproto.repo.createRecord",
                        &pds_body,
                    )
                    .await
                    .map_err(|e| mlua::Error::runtime(format!("PDS createRecord failed: {e}")))?;

                    if !resp.status().is_success() {
                        let status = resp.status();
                        let body = resp.text().await.unwrap_or_default();
                        return Err(mlua::Error::runtime(format!(
                            "PDS createRecord returned {status}: {body}"
                        )));
                    }

                    let bytes = resp.bytes().await.map_err(|e| {
                        mlua::Error::runtime(format!("failed to read PDS response: {e}"))
                    })?;
                    let result: Value = serde_json::from_slice(&bytes)
                        .map_err(|e| mlua::Error::runtime(format!("invalid PDS JSON: {e}")))?;

                    // Upsert local DB
                    if let (Some(uri), Some(cid)) = (
                        result.get("uri").and_then(|v| v.as_str()),
                        result.get("cid").and_then(|v| v.as_str()),
                    ) {
                        let rkey = uri.split('/').next_back().unwrap_or_default();
                        let _ = sqlx::query(
                            r#"INSERT INTO records (uri, did, collection, rkey, record, cid)
                               VALUES ($1, $2, $3, $4, $5, $6)
                               ON CONFLICT (uri) DO UPDATE
                                   SET record = EXCLUDED.record,
                                       cid = EXCLUDED.cid"#,
                        )
                        .bind(uri)
                        .bind(claims.did())
                        .bind(&collection)
                        .bind(rkey)
                        .bind(&data)
                        .bind(cid)
                        .execute(&state.db)
                        .await;
                    }

                    result
                };

                // Write back _uri and _cid
                if let Some(uri) = pds_result.get("uri").and_then(|v| v.as_str()) {
                    this.raw_set("_uri", uri.to_string())?;
                }
                if let Some(cid) = pds_result.get("cid").and_then(|v| v.as_str()) {
                    this.raw_set("_cid", cid.to_string())?;
                }

                Ok(this)
            }
        })?;
        methods.set("save", save_fn)?;
    }

    // :delete()
    {
        let state = state.clone();
        let claims = claims.clone();
        let session = session.clone();
        let delete_fn = lua.create_async_function(move |_lua, this: mlua::Table| {
            let state = state.clone();
            let claims = claims.clone();
            let session = session.clone();
            async move {
                let uri: String = this.raw_get::<Option<String>>("_uri")?.ok_or_else(|| {
                    mlua::Error::runtime("cannot delete a Record that has no _uri")
                })?;
                let collection: String = this.raw_get("_collection")?;

                let rkey = uri
                    .split('/')
                    .next_back()
                    .ok_or_else(|| mlua::Error::runtime("invalid AT URI"))?
                    .to_string();

                let pds_body = json!({
                    "repo": claims.did(),
                    "collection": collection,
                    "rkey": rkey,
                });

                let resp = repo::pds_post_json_raw(
                    &state,
                    &session,
                    "com.atproto.repo.deleteRecord",
                    &pds_body,
                )
                .await
                .map_err(|e| mlua::Error::runtime(format!("PDS deleteRecord failed: {e}")))?;

                if !resp.status().is_success() {
                    let status = resp.status();
                    let body = resp.text().await.unwrap_or_default();
                    return Err(mlua::Error::runtime(format!(
                        "PDS deleteRecord returned {status}: {body}"
                    )));
                }

                // Delete from local DB
                let _ = sqlx::query("DELETE FROM records WHERE uri = $1")
                    .bind(&uri)
                    .execute(&state.db)
                    .await;

                // Clear _uri and _cid
                this.raw_set("_uri", mlua::Value::Nil)?;
                this.raw_set("_cid", mlua::Value::Nil)?;

                Ok(this)
            }
        })?;
        methods.set("delete", delete_fn)?;
    }

    // :set_key_type(type)
    {
        let set_key_type_fn =
            lua.create_function(|_lua, (this, key_type): (mlua::Table, String)| {
                match key_type.as_str() {
                    "tid" | "any" | "nsid" => {}
                    s if s.starts_with("literal:") && s.len() > "literal:".len() => {}
                    _ => {
                        return Err(mlua::Error::runtime(format!(
                            "invalid key type '{key_type}': expected tid, any, nsid, or literal:*"
                        )));
                    }
                }
                this.raw_set("_key_type", key_type)?;
                Ok(this)
            })?;
        methods.set("set_key_type", set_key_type_fn)?;
    }

    // :set_rkey(key)
    {
        let set_rkey_fn = lua.create_function(|_lua, (this, key): (mlua::Table, String)| {
            if key.is_empty() {
                return Err(mlua::Error::runtime("rkey must be a non-empty string"));
            }
            this.raw_set("_rkey", key)?;
            Ok(this)
        })?;
        methods.set("set_rkey", set_rkey_fn)?;
    }

    // :generate_rkey()
    {
        let generate_rkey_fn = lua.create_function(|_lua, this: mlua::Table| {
            let key_type: Option<String> = this.raw_get("_key_type")?;
            let rkey = match key_type.as_deref() {
                Some("tid") | Some("any") => generate_tid(),
                Some(s) if s.starts_with("literal:") => s["literal:".len()..].to_string(),
                Some("nsid") => {
                    return Err(mlua::Error::runtime(
                        "cannot auto-generate rkey for nsid key type — use set_rkey() instead",
                    ));
                }
                Some(other) => {
                    return Err(mlua::Error::runtime(format!("unknown key type '{other}'")));
                }
                None => {
                    return Err(mlua::Error::runtime(
                        "no _key_type set — call set_key_type() first or use a record-type lexicon",
                    ));
                }
            };
            this.raw_set("_rkey", rkey.as_str())?;
            Ok(rkey)
        })?;
        methods.set("generate_rkey", generate_rkey_fn)?;
    }

    // -- metatable --
    let metatable = lua.create_table()?;

    // __index: check methods first, then rawget
    {
        let methods_ref = methods.clone();
        let index_fn = lua.create_function(move |_lua, (this, key): (mlua::Table, String)| {
            // Check methods table first
            let method: mlua::Value = methods_ref.raw_get(key.as_str())?;
            if !method.is_nil() {
                return Ok(method);
            }
            // Fall through to raw field access
            this.raw_get::<mlua::Value>(key.as_str())
        })?;
        metatable.set("__index", index_fn)?;
    }

    // __newindex: block writes to internal fields
    {
        let newindex_fn = lua.create_function(
            move |_lua, (this, key, value): (mlua::Table, String, mlua::Value)| {
                if INTERNAL_FIELDS.contains(&key.as_str()) {
                    return Err(mlua::Error::runtime(format!(
                        "cannot assign to internal field '{key}'"
                    )));
                }
                this.raw_set(key, value)?;
                Ok(())
            },
        )?;
        metatable.set("__newindex", newindex_fn)?;
    }

    // __tostring
    {
        let tostring_fn = lua.create_function(|_lua, this: mlua::Table| {
            let collection: String = this.raw_get("_collection")?;
            let uri: Option<String> = this.raw_get("_uri")?;
            match uri {
                Some(u) => Ok(format!("Record({collection}) [uri={u}]")),
                None => Ok(format!("Record({collection}) [unsaved]")),
            }
        })?;
        metatable.set("__tostring", tostring_fn)?;
    }

    // -- Record constructor function --
    let record_table = lua.create_table()?;

    {
        let state_c = state.clone();
        let metatable_c = metatable.clone();
        let constructor = lua.create_async_function(
            move |lua, (collection, data): (String, Option<mlua::Value>)| {
                let state = state_c.clone();
                let metatable = metatable_c.clone();
                async move {
                    let table = lua.create_table()?;

                    // Look up schema
                    let lexicon = state.lexicons.get(&collection).await;
                    let schema_value: mlua::Value =
                        match lexicon.as_ref().and_then(|l| l.record_schema.as_ref()) {
                            Some(schema_json) => lua.to_value(schema_json)?,
                            None => mlua::Value::Nil,
                        };

                    // Set internal fields
                    table.raw_set("_collection", collection.as_str())?;
                    table.raw_set("_uri", mlua::Value::Nil)?;
                    table.raw_set("_cid", mlua::Value::Nil)?;
                    table.raw_set("_schema", schema_value.clone())?;

                    // Auto-set _key_type from the lexicon's record_key
                    match lexicon.as_ref().and_then(|l| l.record_key.as_deref()) {
                        Some(key) => table.raw_set("_key_type", key)?,
                        None => table.raw_set("_key_type", mlua::Value::Nil)?,
                    }
                    table.raw_set("_rkey", mlua::Value::Nil)?;

                    // Copy fields from data if provided
                    if let Some(mlua::Value::Table(data_table)) = data {
                        for pair in data_table.pairs::<mlua::Value, mlua::Value>() {
                            let (k, v) = pair?;
                            table.raw_set(k, v)?;
                        }
                    }

                    // Populate defaults from schema
                    if let mlua::Value::Table(ref schema_table) = schema_value {
                        populate_defaults(&lua, &table, schema_table)?;
                    }

                    table.set_metatable(Some(metatable))?;
                    Ok(table)
                }
            },
        )?;
        record_table.set("new", constructor)?;
    }

    // -- Static methods --

    // Record.save_all(records)
    {
        let state = state.clone();
        let claims = claims.clone();
        let session = session.clone();
        let save_all_fn =
            lua.create_async_function(move |lua, records_table: mlua::Table| {
                let state = state.clone();
                let claims = claims.clone();
                let session = session.clone();
                async move {
                    // Extract save data from each record (sync)
                    type SaveItem = (mlua::Table, String, Option<String>, Option<String>, Value);
                    let mut save_items: Vec<SaveItem> = Vec::new();

                    for pair in records_table.sequence_values::<mlua::Table>() {
                        let record_table = pair?;
                        let collection: String = record_table.raw_get("_collection")?;
                        let existing_uri: Option<String> = record_table.raw_get("_uri")?;
                        let rkey: Option<String> = record_table.raw_get("_rkey")?;

                        // Validate
                        let schema: mlua::Value = record_table.raw_get("_schema")?;
                        if let mlua::Value::Table(ref schema_table) = schema {
                            validate_required_fields(&record_table, schema_table)?;
                        }

                        let data = extract_record_data(&lua, &record_table, &collection)?;
                        save_items.push((record_table, collection, existing_uri, rkey, data));
                    }

                    // Parallel PDS calls
                    let futs = save_items.iter().map(|(_, collection, existing_uri, rkey, data)| {
                        let state = state.clone();
                        let claims = claims.clone();
                        let session = session.clone();
                        let collection = collection.clone();
                        let existing_uri = existing_uri.clone();
                        let rkey = rkey.clone();
                        let data = data.clone();
                        async move {
                            if let Some(ref uri) = existing_uri {
                                let rkey = uri
                                    .split('/')
                                    .next_back()
                                    .ok_or_else(|| mlua::Error::runtime("invalid AT URI"))?
                                    .to_string();

                                let pds_body = json!({
                                    "repo": claims.did(),
                                    "collection": collection,
                                    "rkey": rkey,
                                    "record": data,
                                });

                                let resp = repo::pds_post_json_raw(
                                    &state,
                                    &session,
                                    "com.atproto.repo.putRecord",
                                    &pds_body,
                                )
                                .await
                                .map_err(|e| {
                                    mlua::Error::runtime(format!("PDS putRecord failed: {e}"))
                                })?;

                                if !resp.status().is_success() {
                                    let status = resp.status();
                                    let body = resp.text().await.unwrap_or_default();
                                    return Err(mlua::Error::runtime(format!(
                                        "PDS putRecord returned {status}: {body}"
                                    )));
                                }

                                let bytes = resp.bytes().await.map_err(|e| {
                                    mlua::Error::runtime(format!(
                                        "failed to read PDS response: {e}"
                                    ))
                                })?;
                                let result: Value = serde_json::from_slice(&bytes).map_err(
                                    |e| mlua::Error::runtime(format!("invalid PDS JSON: {e}")),
                                )?;

                                let cid = result
                                    .get("cid")
                                    .and_then(|v| v.as_str())
                                    .unwrap_or_default();
                                let _ = sqlx::query(
                                    r#"INSERT INTO records (uri, did, collection, rkey, record, cid)
                                       VALUES ($1, $2, $3, $4, $5, $6)
                                       ON CONFLICT (uri) DO UPDATE
                                           SET record = EXCLUDED.record,
                                               cid = EXCLUDED.cid,
                                               indexed_at = NOW()"#,
                                )
                                .bind(uri.as_str())
                                .bind(claims.did())
                                .bind(&collection)
                                .bind(&rkey)
                                .bind(&data)
                                .bind(cid)
                                .execute(&state.db)
                                .await;

                                Ok(result)
                            } else {
                                let mut pds_body = json!({
                                    "repo": claims.did(),
                                    "collection": collection,
                                    "record": data,
                                });
                                if let Some(ref rkey) = rkey {
                                    pds_body["rkey"] = json!(rkey);
                                }

                                let resp = repo::pds_post_json_raw(
                                    &state,
                                    &session,
                                    "com.atproto.repo.createRecord",
                                    &pds_body,
                                )
                                .await
                                .map_err(|e| {
                                    mlua::Error::runtime(format!(
                                        "PDS createRecord failed: {e}"
                                    ))
                                })?;

                                if !resp.status().is_success() {
                                    let status = resp.status();
                                    let body = resp.text().await.unwrap_or_default();
                                    return Err(mlua::Error::runtime(format!(
                                        "PDS createRecord returned {status}: {body}"
                                    )));
                                }

                                let bytes = resp.bytes().await.map_err(|e| {
                                    mlua::Error::runtime(format!(
                                        "failed to read PDS response: {e}"
                                    ))
                                })?;
                                let result: Value = serde_json::from_slice(&bytes).map_err(
                                    |e| mlua::Error::runtime(format!("invalid PDS JSON: {e}")),
                                )?;

                                if let (Some(uri), Some(cid)) = (
                                    result.get("uri").and_then(|v| v.as_str()),
                                    result.get("cid").and_then(|v| v.as_str()),
                                ) {
                                    let rkey =
                                        uri.split('/').next_back().unwrap_or_default();
                                    let _ = sqlx::query(
                                        r#"INSERT INTO records (uri, did, collection, rkey, record, cid)
                                           VALUES ($1, $2, $3, $4, $5, $6)
                                           ON CONFLICT (uri) DO UPDATE
                                               SET record = EXCLUDED.record,
                                                   cid = EXCLUDED.cid"#,
                                    )
                                    .bind(uri)
                                    .bind(claims.did())
                                    .bind(&collection)
                                    .bind(rkey)
                                    .bind(&data)
                                    .bind(cid)
                                    .execute(&state.db)
                                    .await;
                                }

                                Ok(result)
                            }
                        }
                    });

                    let results = try_join_all(futs).await?;

                    // Write back _uri and _cid (sync)
                    for (i, (record_table, _, _, _, _)) in save_items.iter().enumerate() {
                        if let Some(result) = results.get(i) {
                            if let Some(uri) = result.get("uri").and_then(|v| v.as_str()) {
                                record_table.raw_set("_uri", uri.to_string())?;
                            }
                            if let Some(cid) = result.get("cid").and_then(|v| v.as_str()) {
                                record_table.raw_set("_cid", cid.to_string())?;
                            }
                        }
                    }

                    lua.to_value(&results)
                }
            })?;
        record_table.set("save_all", save_all_fn)?;
    }

    // Record.load(uri)
    {
        let state = state.clone();
        let metatable_c = metatable.clone();
        let load_fn = lua.create_async_function(move |lua, uri: String| {
            let state = state.clone();
            let metatable = metatable_c.clone();
            async move {
                let row: Option<(String, Value, String)> =
                    sqlx::query_as("SELECT collection, record, cid FROM records WHERE uri = $1")
                        .bind(&uri)
                        .fetch_optional(&state.db)
                        .await
                        .map_err(|e| mlua::Error::runtime(format!("DB query failed: {e}")))?;

                match row {
                    Some((collection, record, cid)) => {
                        let table = lua.create_table()?;

                        // Look up schema
                        let lexicon = state.lexicons.get(&collection).await;
                        let schema_value: mlua::Value =
                            match lexicon.as_ref().and_then(|l| l.record_schema.as_ref()) {
                                Some(schema_json) => lua.to_value(schema_json)?,
                                None => mlua::Value::Nil,
                            };

                        table.raw_set("_collection", collection.as_str())?;
                        table.raw_set("_uri", uri.as_str())?;
                        table.raw_set("_cid", cid.as_str())?;
                        table.raw_set("_schema", schema_value)?;
                        table.raw_set("_key_type", mlua::Value::Nil)?;
                        table.raw_set("_rkey", mlua::Value::Nil)?;

                        // Copy record fields
                        if let Some(obj) = record.as_object() {
                            for (k, v) in obj {
                                if k == "$type" {
                                    continue;
                                }
                                let lua_val: mlua::Value = lua.to_value(v)?;
                                table.raw_set(k.as_str(), lua_val)?;
                            }
                        }

                        table.set_metatable(Some(metatable))?;
                        Ok(mlua::Value::Table(table))
                    }
                    None => Ok(mlua::Value::Nil),
                }
            }
        })?;
        record_table.set("load", load_fn)?;
    }

    // Record.load_all(uris)
    {
        let state = state;
        let metatable_c = metatable;
        let load_all_fn = lua.create_async_function(move |lua, uris_table: mlua::Table| {
            let state = state.clone();
            let metatable = metatable_c.clone();
            async move {
                let uris: Vec<String> = lua.from_value(mlua::Value::Table(uris_table))?;

                let futs = uris.iter().map(|uri| {
                    let state = state.clone();
                    let uri = uri.clone();
                    async move {
                        let row: Option<(String, Value, String)> = sqlx::query_as(
                            "SELECT collection, record, cid FROM records WHERE uri = $1",
                        )
                        .bind(&uri)
                        .fetch_optional(&state.db)
                        .await
                        .map_err(|e| mlua::Error::runtime(format!("DB query failed: {e}")))?;

                        let result: Result<_, mlua::Error> =
                            Ok(row.map(|(collection, record, cid)| (uri, collection, record, cid)));
                        result
                    }
                });

                let results: Vec<Option<(String, String, Value, String)>> =
                    try_join_all(futs).await?;

                let out = lua.create_table()?;
                for (i, item) in results.into_iter().enumerate() {
                    match item {
                        Some((uri, collection, record, cid)) => {
                            let table = lua.create_table()?;

                            let lexicon = state.lexicons.get(&collection).await;
                            let schema_value: mlua::Value =
                                match lexicon.as_ref().and_then(|l| l.record_schema.as_ref()) {
                                    Some(schema_json) => lua.to_value(schema_json)?,
                                    None => mlua::Value::Nil,
                                };

                            table.raw_set("_collection", collection.as_str())?;
                            table.raw_set("_uri", uri.as_str())?;
                            table.raw_set("_cid", cid.as_str())?;
                            table.raw_set("_schema", schema_value)?;
                            table.raw_set("_key_type", mlua::Value::Nil)?;
                            table.raw_set("_rkey", mlua::Value::Nil)?;

                            if let Some(obj) = record.as_object() {
                                for (k, v) in obj {
                                    if k == "$type" {
                                        continue;
                                    }
                                    let lua_val: mlua::Value = lua.to_value(v)?;
                                    table.raw_set(k.as_str(), lua_val)?;
                                }
                            }

                            table.set_metatable(Some(metatable.clone()))?;
                            out.raw_set(i + 1, table)?;
                        }
                        None => {
                            out.raw_set(i + 1, mlua::Value::Nil)?;
                        }
                    }
                }

                Ok(mlua::Value::Table(out))
            }
        })?;
        record_table.set("load_all", load_all_fn)?;
    }

    // -- Make Record callable via __call metamethod --
    let record_mt = lua.create_table()?;
    {
        let new_fn: mlua::Function = record_table.get("new")?;
        let call_fn =
            lua.create_async_function(
                move |_lua,
                      (_self_table, collection, data): (
                    mlua::Table,
                    String,
                    Option<mlua::Value>,
                )| {
                    let new_fn = new_fn.clone();
                    async move {
                        let result: mlua::Table = new_fn.call_async((collection, data)).await?;
                        Ok(result)
                    }
                },
            )?;
        record_mt.set("__call", call_fn)?;
    }
    record_table.set_metatable(Some(record_mt))?;

    lua.globals().set("Record", record_table)?;
    Ok(())
}

/// Check that all required fields (per schema) are present and non-nil.
fn validate_required_fields(table: &mlua::Table, schema: &mlua::Table) -> LuaResult<()> {
    let required: Option<mlua::Table> = schema.raw_get("required")?;
    if let Some(required) = required {
        for pair in required.sequence_values::<String>() {
            let field = pair?;
            let val: mlua::Value = table.raw_get(field.as_str())?;
            if val.is_nil() {
                return Err(mlua::Error::runtime(format!(
                    "missing required field '{field}'"
                )));
            }
        }
    }
    Ok(())
}

/// Set missing fields from schema property defaults.
fn populate_defaults(lua: &Lua, table: &mlua::Table, schema: &mlua::Table) -> LuaResult<()> {
    let properties: Option<mlua::Table> = schema.raw_get("properties")?;
    if let Some(properties) = properties {
        for pair in properties.pairs::<String, mlua::Table>() {
            let (key, prop_def) = pair?;
            // Skip internal fields
            if key.starts_with('_') {
                continue;
            }
            let existing: mlua::Value = table.raw_get(key.as_str())?;
            if existing.is_nil() {
                let default: mlua::Value = prop_def.raw_get("default")?;
                if !default.is_nil() {
                    table.raw_set(key.as_str(), lua.to_value(&default)?)?;
                }
            }
        }
    }
    Ok(())
}

/// Serialize a Record table to serde_json::Value, stripping _-prefixed keys,
/// filtering to only schema-defined properties, and injecting $type.
fn extract_record_data(lua: &Lua, table: &mlua::Table, collection: &str) -> LuaResult<Value> {
    // Build the set of allowed property names from the schema (if available).
    // When a schema is present, only fields listed in `properties` are included.
    let schema: mlua::Value = table.raw_get("_schema")?;
    let allowed: Option<Vec<String>> = if let mlua::Value::Table(ref schema_table) = schema {
        let properties: Option<mlua::Table> = schema_table.raw_get("properties")?;
        properties.map(|props| {
            props
                .pairs::<String, mlua::Value>()
                .filter_map(|pair| pair.ok().map(|(k, _)| k))
                .collect()
        })
    } else {
        None
    };

    let tmp = lua.create_table()?;
    for pair in table.pairs::<String, mlua::Value>() {
        let (k, v) = pair?;
        if k.starts_with('_') {
            continue;
        }
        if let Some(ref keys) = allowed
            && !keys.iter().any(|a| a == &k)
        {
            continue;
        }
        tmp.raw_set(k, v)?;
    }

    let mut data: Value = lua.from_value(mlua::Value::Table(tmp))?;
    if let Some(obj) = data.as_object_mut() {
        obj.insert("$type".to_string(), json!(collection));
    }
    Ok(data)
}
