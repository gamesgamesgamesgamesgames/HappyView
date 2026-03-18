use base64::{Engine, engine::general_purpose::STANDARD as BASE64};
use mlua::{Lua, LuaSerdeExt, Result as LuaResult};
use serde_json::{Value, json};
use sqlx::{Column, Row};
use std::sync::Arc;

use crate::AppState;
use crate::db::{DatabaseBackend, adapt_sql};

/// Encode a cursor from created_at timestamp and uri.
fn encode_cursor(created_at: &str, uri: &str) -> String {
    BASE64.encode(format!("{created_at}|{uri}"))
}

/// Decode a cursor into (created_at, uri). Returns None if invalid.
fn decode_cursor(cursor: &str) -> Option<(String, String)> {
    let decoded = BASE64.decode(cursor).ok()?;
    let s = String::from_utf8(decoded).ok()?;
    let (ts, uri) = s.split_once('|')?;
    Some((ts.to_string(), uri.to_string()))
}

/// Register the `db` table with database query functions.
pub fn register_db_api(lua: &Lua, state: Arc<AppState>) -> LuaResult<()> {
    let db_table = lua.create_table()?;

    // db.query({ collection, did?, limit?, offset?, cursor?, sort?, sortDirection? }) -> { records, cursor? }
    let state_query = state.clone();
    let query_fn = lua.create_async_function(move |lua, opts: mlua::Table| {
        let state = state_query.clone();
        async move {
            let backend = state.db_backend;
            let collection: String = opts.get("collection")?;
            let did: Option<String> = opts.get("did").ok();
            let limit: i64 = opts.get::<i64>("limit").unwrap_or(20).min(100);
            let sort: Option<String> = opts.get("sort").ok();
            let sort_direction: Option<String> = opts.get("sortDirection").ok();
            let cursor_str: Option<String> = opts.get("cursor").ok();

            // Validate sort field name to prevent SQL injection
            if let Some(ref field) = sort {
                let valid = field.chars().all(|c| c.is_ascii_alphanumeric() || c == '_');
                if !valid || field.is_empty() {
                    return Err(mlua::Error::runtime(
                        "invalid sort field: only alphanumeric characters and underscores are allowed",
                    ));
                }
            }

            let direction = match sort_direction.as_deref() {
                Some("asc") => "ASC",
                Some("desc") => "DESC",
                None => "DESC",
                Some(other) => {
                    return Err(mlua::Error::runtime(format!(
                        "invalid sortDirection '{other}': must be 'asc' or 'desc'"
                    )));
                }
            };

            let result_table = lua.create_table()?;

            if let Some(ref sort_field) = sort {
                // Custom sort: use OFFSET/LIMIT with base64-encoded offset cursor
                let offset: i64 = if let Some(ref cursor) = cursor_str {
                    BASE64.decode(cursor).ok()
                        .and_then(|b| String::from_utf8(b).ok())
                        .and_then(|s| s.parse::<i64>().ok())
                        .unwrap_or(0)
                } else {
                    opts.get::<i64>("offset").unwrap_or(0)
                };

                let top_level_columns = ["indexed_at", "did", "uri"];
                let order_expr = if top_level_columns.contains(&sort_field.as_str()) {
                    format!("{sort_field} {direction}")
                } else {
                    match backend {
                        DatabaseBackend::Sqlite => format!("json_extract(record, '$.value.{sort_field}') {direction}"),
                        DatabaseBackend::Postgres => format!("record::jsonb->'value'->>'{sort_field}' {direction}"),
                    }
                };

                let rows: Vec<(String, String, String)> = if let Some(ref did) = did {
                    let sql = adapt_sql(
                        &format!("SELECT uri, did, record FROM records WHERE collection = ? AND did = ? ORDER BY {order_expr} LIMIT ? OFFSET ?"),
                        backend,
                    );
                    sqlx::query_as(&sql)
                    .bind(&collection)
                    .bind(did)
                    .bind(limit)
                    .bind(offset)
                    .fetch_all(&state.db)
                    .await
                    .map_err(|e| mlua::Error::runtime(format!("DB query failed: {e}")))?
                } else {
                    let sql = adapt_sql(
                        &format!("SELECT uri, did, record FROM records WHERE collection = ? ORDER BY {order_expr} LIMIT ? OFFSET ?"),
                        backend,
                    );
                    sqlx::query_as(&sql)
                    .bind(&collection)
                    .bind(limit)
                    .bind(offset)
                    .fetch_all(&state.db)
                    .await
                    .map_err(|e| mlua::Error::runtime(format!("DB query failed: {e}")))?
                };

                let has_next = rows.len() as i64 == limit;

                if has_next {
                    let next_offset = offset + limit;
                    result_table.set("cursor", BASE64.encode(next_offset.to_string()))?;
                }

                let records: Vec<Value> = rows
                    .into_iter()
                    .map(|(uri, _did, record_str)| {
                        let mut record: Value = serde_json::from_str(&record_str).unwrap_or(json!({}));
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
                result_table.set("records", records_table)?;
            } else {
                // Cursor-based pagination on (created_at, uri)
                let cursor_parts = cursor_str.as_ref().and_then(|c| decode_cursor(c));

                type RowType = (String, String, String, String);

                let rows_raw: Vec<RowType> = match (&did, &cursor_parts) {
                    (Some(did), Some((cursor_ts, cursor_uri))) => {
                        let sql = adapt_sql(
                            "SELECT uri, did, record, created_at FROM records \
                             WHERE collection = ? AND did = ? AND (created_at < ? OR (created_at = ? AND uri < ?)) \
                             ORDER BY created_at DESC, uri DESC \
                             LIMIT ?",
                            backend,
                        );
                        sqlx::query_as(&sql)
                        .bind(&collection)
                        .bind(did)
                        .bind(cursor_ts)
                        .bind(cursor_ts)
                        .bind(cursor_uri)
                        .bind(limit)
                        .fetch_all(&state.db)
                        .await
                        .map_err(|e| mlua::Error::runtime(format!("DB query failed: {e}")))?
                    }
                    (Some(did), None) => {
                        let sql = adapt_sql(
                            "SELECT uri, did, record, created_at FROM records \
                             WHERE collection = ? AND did = ? \
                             ORDER BY created_at DESC, uri DESC \
                             LIMIT ?",
                            backend,
                        );
                        sqlx::query_as(&sql)
                        .bind(&collection)
                        .bind(did)
                        .bind(limit)
                        .fetch_all(&state.db)
                        .await
                        .map_err(|e| mlua::Error::runtime(format!("DB query failed: {e}")))?
                    }
                    (None, Some((cursor_ts, cursor_uri))) => {
                        let sql = adapt_sql(
                            "SELECT uri, did, record, created_at FROM records \
                             WHERE collection = ? AND (created_at < ? OR (created_at = ? AND uri < ?)) \
                             ORDER BY created_at DESC, uri DESC \
                             LIMIT ?",
                            backend,
                        );
                        sqlx::query_as(&sql)
                        .bind(&collection)
                        .bind(cursor_ts)
                        .bind(cursor_ts)
                        .bind(cursor_uri)
                        .bind(limit)
                        .fetch_all(&state.db)
                        .await
                        .map_err(|e| mlua::Error::runtime(format!("DB query failed: {e}")))?
                    }
                    (None, None) => {
                        let sql = adapt_sql(
                            "SELECT uri, did, record, created_at FROM records \
                             WHERE collection = ? \
                             ORDER BY created_at DESC, uri DESC \
                             LIMIT ?",
                            backend,
                        );
                        sqlx::query_as(&sql)
                        .bind(&collection)
                        .bind(limit)
                        .fetch_all(&state.db)
                        .await
                        .map_err(|e| mlua::Error::runtime(format!("DB query failed: {e}")))?
                    }
                };

                let has_next = rows_raw.len() as i64 == limit;

                if has_next
                    && let Some((last_uri, _, _, last_created_at)) = rows_raw.last()
                {
                    let cursor = encode_cursor(last_created_at, last_uri);
                    result_table.set("cursor", cursor)?;
                }

                let records: Vec<Value> = rows_raw
                    .into_iter()
                    .map(|(uri, _did, record_str, _created_at)| {
                        let mut record: Value = serde_json::from_str(&record_str).unwrap_or(json!({}));
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
                result_table.set("records", records_table)?;
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
            let backend = state.db_backend;
            let sql = adapt_sql("SELECT record FROM records WHERE uri = ?", backend);
            let row: Option<(String,)> = sqlx::query_as(&sql)
                .bind(&uri)
                .fetch_optional(&state.db)
                .await
                .map_err(|e| mlua::Error::runtime(format!("DB query failed: {e}")))?;

            match row {
                Some((record_str,)) => {
                    let mut record: Value = serde_json::from_str(&record_str).unwrap_or(json!({}));
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
            let backend = state.db_backend;
            let collection: String = opts.get("collection")?;
            let field: String = opts.get("field")?;
            let query: String = opts.get("query")?;
            let limit: i64 = opts.get::<i64>("limit").unwrap_or(10).min(100);

            // Validate field name to prevent SQL injection
            let valid = field.chars().all(|c| c.is_ascii_alphanumeric() || c == '_');
            if !valid || field.is_empty() {
                return Err(mlua::Error::runtime(
                    "invalid search field: only alphanumeric characters and underscores are allowed",
                ));
            }

            let like_pattern = format!("%{query}%");

            // Cannot use adapt_sql: Postgres reuses $3 for two bind positions,
            // while SQLite needs separate ? for each. Different bind counts.
            let rows: Vec<(String, String, String)> = match backend {
                DatabaseBackend::Sqlite => {
                    let sql = format!(
                        "SELECT uri, did, record FROM records \
                         WHERE collection = ? \
                           AND json_extract(record, '$.{field}') LIKE ? COLLATE NOCASE \
                         ORDER BY \
                           CASE \
                             WHEN LOWER(json_extract(record, '$.{field}')) = LOWER(?) THEN 0 \
                             WHEN LOWER(json_extract(record, '$.{field}')) LIKE LOWER(?) || '%' THEN 1 \
                             ELSE 2 \
                           END, \
                           json_extract(record, '$.{field}') \
                         LIMIT ?"
                    );
                    sqlx::query_as(&sql)
                    .bind(&collection)
                    .bind(&like_pattern)
                    .bind(&query)
                    .bind(&query)
                    .bind(limit)
                    .fetch_all(&state.db)
                    .await
                    .map_err(|e| mlua::Error::runtime(format!("DB search failed: {e}")))?
                }
                DatabaseBackend::Postgres => {
                    let sql = format!(
                        "SELECT uri, did, record FROM records \
                         WHERE collection = $1 \
                           AND record::jsonb->>'{field}' ILIKE $2 \
                         ORDER BY \
                           CASE \
                             WHEN LOWER(record::jsonb->>'{field}') = LOWER($3) THEN 0 \
                             WHEN LOWER(record::jsonb->>'{field}') LIKE LOWER($3) || '%' THEN 1 \
                             ELSE 2 \
                           END, \
                           record::jsonb->>'{field}' \
                         LIMIT $4"
                    );
                    sqlx::query_as(&sql)
                    .bind(&collection)
                    .bind(&like_pattern)
                    .bind(&query)
                    .bind(limit)
                    .fetch_all(&state.db)
                    .await
                    .map_err(|e| mlua::Error::runtime(format!("DB search failed: {e}")))?
                }
            };

            let records: Vec<Value> = rows
                .into_iter()
                .map(|(uri, _did, record_str)| {
                    let mut record: Value = serde_json::from_str(&record_str).unwrap_or(json!({}));
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
                let backend = state.db_backend;
                let count: (i64,) = if let Some(ref did) = did {
                    let sql = adapt_sql(
                        "SELECT COUNT(*) FROM records WHERE collection = ? AND did = ?",
                        backend,
                    );
                    sqlx::query_as(&sql)
                        .bind(&collection)
                        .bind(did)
                        .fetch_one(&state.db)
                        .await
                        .map_err(|e| mlua::Error::runtime(format!("DB count failed: {e}")))?
                } else {
                    let sql =
                        adapt_sql("SELECT COUNT(*) FROM records WHERE collection = ?", backend);
                    sqlx::query_as(&sql)
                        .bind(&collection)
                        .fetch_one(&state.db)
                        .await
                        .map_err(|e| mlua::Error::runtime(format!("DB count failed: {e}")))?
                };
                Ok(count.0)
            }
        })?;
    db_table.set("count", count_fn)?;

    // db.backlinks({ collection, uri, did?, limit?, cursor? }) -> { records, cursor? }
    // Find records in `collection` that reference the given AT URI via record_refs.
    let state_backlinks = state.clone();
    let backlinks_fn = lua.create_async_function(move |lua, opts: mlua::Table| {
        let state = state_backlinks.clone();
        async move {
            let backend = state.db_backend;
            let collection: String = opts.get("collection")?;
            let uri: String = opts.get("uri")?;
            let did: Option<String> = opts.get("did").ok();
            let limit: i64 = opts.get::<i64>("limit").unwrap_or(20).min(100);
            let cursor_str: Option<String> = opts.get("cursor").ok();

            let cursor_parts = cursor_str.as_ref().and_then(|c| decode_cursor(c));

            type RowType = (String, String, String, String);

            let rows_raw: Vec<RowType> = match (&did, &cursor_parts) {
                (Some(did), Some((cursor_ts, cursor_uri))) => {
                    let sql = adapt_sql(
                        "SELECT r.uri, r.did, r.record, r.created_at FROM records r \
                         INNER JOIN record_refs ref ON ref.source_uri = r.uri \
                         WHERE ref.target_uri = ? AND ref.collection = ? AND r.did = ? \
                         AND (r.created_at < ? OR (r.created_at = ? AND r.uri < ?)) \
                         ORDER BY r.created_at DESC, r.uri DESC \
                         LIMIT ?",
                        backend,
                    );
                    sqlx::query_as(&sql)
                        .bind(&uri)
                        .bind(&collection)
                        .bind(did)
                        .bind(cursor_ts)
                        .bind(cursor_ts)
                        .bind(cursor_uri)
                        .bind(limit)
                        .fetch_all(&state.db)
                        .await
                        .map_err(|e| mlua::Error::runtime(format!("DB backlinks failed: {e}")))?
                }
                (Some(did), None) => {
                    let sql = adapt_sql(
                        "SELECT r.uri, r.did, r.record, r.created_at FROM records r \
                         INNER JOIN record_refs ref ON ref.source_uri = r.uri \
                         WHERE ref.target_uri = ? AND ref.collection = ? AND r.did = ? \
                         ORDER BY r.created_at DESC, r.uri DESC \
                         LIMIT ?",
                        backend,
                    );
                    sqlx::query_as(&sql)
                        .bind(&uri)
                        .bind(&collection)
                        .bind(did)
                        .bind(limit)
                        .fetch_all(&state.db)
                        .await
                        .map_err(|e| mlua::Error::runtime(format!("DB backlinks failed: {e}")))?
                }
                (None, Some((cursor_ts, cursor_uri))) => {
                    let sql = adapt_sql(
                        "SELECT r.uri, r.did, r.record, r.created_at FROM records r \
                         INNER JOIN record_refs ref ON ref.source_uri = r.uri \
                         WHERE ref.target_uri = ? AND ref.collection = ? \
                         AND (r.created_at < ? OR (r.created_at = ? AND r.uri < ?)) \
                         ORDER BY r.created_at DESC, r.uri DESC \
                         LIMIT ?",
                        backend,
                    );
                    sqlx::query_as(&sql)
                        .bind(&uri)
                        .bind(&collection)
                        .bind(cursor_ts)
                        .bind(cursor_ts)
                        .bind(cursor_uri)
                        .bind(limit)
                        .fetch_all(&state.db)
                        .await
                        .map_err(|e| mlua::Error::runtime(format!("DB backlinks failed: {e}")))?
                }
                (None, None) => {
                    let sql = adapt_sql(
                        "SELECT r.uri, r.did, r.record, r.created_at FROM records r \
                         INNER JOIN record_refs ref ON ref.source_uri = r.uri \
                         WHERE ref.target_uri = ? AND ref.collection = ? \
                         ORDER BY r.created_at DESC, r.uri DESC \
                         LIMIT ?",
                        backend,
                    );
                    sqlx::query_as(&sql)
                        .bind(&uri)
                        .bind(&collection)
                        .bind(limit)
                        .fetch_all(&state.db)
                        .await
                        .map_err(|e| mlua::Error::runtime(format!("DB backlinks failed: {e}")))?
                }
            };

            let has_next = rows_raw.len() as i64 == limit;

            let result_table = lua.create_table()?;

            if has_next && let Some((last_uri, _, _, last_created_at)) = rows_raw.last() {
                let cursor = encode_cursor(last_created_at, last_uri);
                result_table.set("cursor", cursor)?;
            }

            let records: Vec<Value> = rows_raw
                .into_iter()
                .map(|(uri, _did, record_str, _created_at)| {
                    let mut record: Value = serde_json::from_str(&record_str).unwrap_or(json!({}));
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
            result_table.set("records", records_table)?;

            Ok(mlua::Value::Table(result_table))
        }
    })?;
    db_table.set("backlinks", backlinks_fn)?;

    // db.raw(sql, params?) -> rows[]
    let state_raw = state;
    let raw_fn =
        lua.create_async_function(move |lua, (sql, params): (String, Option<mlua::Table>)| {
            let state = state_raw.clone();
            async move {
                let backend = state.db_backend;
                let adapted = adapt_sql(&sql, backend);
                let mut query = sqlx::query(&adapted);
                if let Some(ref params_table) = params {
                    for value in params_table.sequence_values::<mlua::Value>() {
                        let value = value?;
                        query = match value {
                            mlua::Value::String(s) => query.bind(s.to_str()?.to_string()),
                            mlua::Value::Integer(n) => query.bind(n),
                            mlua::Value::Number(n) => query.bind(n),
                            mlua::Value::Boolean(b) => query.bind(if b { 1_i32 } else { 0_i32 }),
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
                        let lua_val: mlua::Value = match row.try_get::<String, _>(name) {
                            Ok(s) => mlua::Value::String(lua.create_string(&s)?),
                            Err(_) => match row.try_get::<i64, _>(name) {
                                Ok(n) => mlua::Value::Integer(n),
                                Err(_) => match row.try_get::<i32, _>(name) {
                                    Ok(n) => mlua::Value::Integer(n as i64),
                                    Err(_) => match row.try_get::<f64, _>(name) {
                                        Ok(n) => mlua::Value::Number(n),
                                        Err(_) => match row.try_get::<bool, _>(name) {
                                            Ok(b) => mlua::Value::Boolean(b),
                                            Err(_) => mlua::Value::Nil,
                                        },
                                    },
                                },
                            },
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::Config;
    use crate::db::DatabaseBackend;
    use crate::lexicon::LexiconRegistry;
    use tokio::sync::watch;

    fn test_state() -> AppState {
        let config = Config {
            host: "127.0.0.1".into(),
            port: 3000,
            database_url: String::new(),
            database_backend: crate::db::DatabaseBackend::Sqlite,
            public_url: String::new(),
            session_secret: "test-secret".into(),
            tap_url: String::new(),
            tap_admin_password: None,
            relay_url: String::new(),
            plc_url: String::new(),
            static_dir: String::new(),
            event_log_retention_days: 30,
        };
        let (tx, _) = watch::channel(vec![]);
        let (labeler_tx, _) = watch::channel(());
        sqlx::any::install_default_drivers();
        let test_db = sqlx::AnyPool::connect_lazy("sqlite::memory:").unwrap();
        let atrium_http = std::sync::Arc::new(atrium_oauth::DefaultHttpClient::default());
        let did_resolver = atrium_identity::did::CommonDidResolver::new(
            atrium_identity::did::CommonDidResolverConfig {
                plc_directory_url: "https://plc.directory".into(),
                http_client: std::sync::Arc::clone(&atrium_http),
            },
        );
        let handle_resolver = atrium_identity::handle::AtprotoHandleResolver::new(
            atrium_identity::handle::AtprotoHandleResolverConfig {
                dns_txt_resolver: crate::dns::NativeDnsResolver::new(),
                http_client: atrium_http,
            },
        );
        let oauth = atrium_oauth::OAuthClient::new(atrium_oauth::OAuthClientConfig {
            client_metadata: atrium_oauth::AtprotoLocalhostClientMetadata {
                redirect_uris: Some(vec!["http://127.0.0.1:0/auth/callback".into()]),
                scopes: Some(vec![atrium_oauth::Scope::Known(
                    atrium_oauth::KnownScope::Atproto,
                )]),
            },
            keys: None,
            state_store: crate::auth::oauth_store::DbStateStore::new(
                test_db.clone(),
                crate::db::DatabaseBackend::Sqlite,
            ),
            session_store: crate::auth::oauth_store::DbSessionStore::new(
                test_db.clone(),
                crate::db::DatabaseBackend::Sqlite,
            ),
            resolver: atrium_oauth::OAuthResolverConfig {
                did_resolver,
                handle_resolver,
                authorization_server_metadata: Default::default(),
                protected_resource_metadata: Default::default(),
            },
        })
        .expect("Failed to create test OAuth client");
        AppState {
            config,
            http: reqwest::Client::new(),
            db: test_db,
            db_backend: DatabaseBackend::Sqlite,
            lexicons: LexiconRegistry::new(),
            collections_tx: tx,
            labeler_subscriptions_tx: labeler_tx,
            rate_limiter: crate::rate_limit::RateLimiter::new(
                false,
                crate::rate_limit::RateLimitConfig {
                    capacity: 100,
                    refill_rate: 2.0,
                    default_query_cost: 1,
                    default_procedure_cost: 1,
                    default_proxy_cost: 1,
                },
                vec![],
            ),
            oauth: std::sync::Arc::new(oauth),
            cookie_key: axum_extra::extract::cookie::Key::derive_from(
                b"test-secret-for-tests-only-not-production",
            ),
        }
    }

    fn setup(state: &AppState) -> Lua {
        let lua = Lua::new();
        register_db_api(&lua, Arc::new(state.clone())).unwrap();
        lua
    }

    #[tokio::test]
    async fn raw_allows_non_select() {
        let state = test_state();
        let lua = setup(&state);
        let result: Result<mlua::Value, _> = lua
            .load(r#"return db.raw("DELETE FROM records")"#)
            .eval_async()
            .await;
        // Should fail with a DB connection error, NOT a validation error
        assert!(result.is_err());
        let err = result.unwrap_err().to_string();
        assert!(
            !err.contains("only supports SELECT"),
            "should have passed validation but got: {err}"
        );
    }

    #[tokio::test]
    async fn raw_allows_select() {
        let state = test_state();
        let lua = setup(&state);
        let result: Result<mlua::Value, _> =
            lua.load(r#"return db.raw("SELECT 1")"#).eval_async().await;
        // Should either succeed (SQLite in-memory) or fail with a DB connection error,
        // but NOT a validation error.
        if let Err(e) = &result {
            let err = e.to_string();
            assert!(
                !err.contains("only supports SELECT"),
                "should have passed validation but got: {err}"
            );
        }
    }

    #[tokio::test]
    async fn query_rejects_invalid_sort_field() {
        let state = test_state();
        let lua = setup(&state);
        let result: Result<mlua::Value, _> = lua
            .load(r#"return db.query({ collection = "test", sort = "name; DROP TABLE" })"#)
            .eval_async()
            .await;
        assert!(result.is_err());
        let err = result.unwrap_err().to_string();
        assert!(
            err.contains("invalid sort field"),
            "expected sort field error, got: {err}"
        );
    }

    #[tokio::test]
    async fn query_rejects_invalid_sort_direction() {
        let state = test_state();
        let lua = setup(&state);
        let result: Result<mlua::Value, _> = lua
            .load(r#"return db.query({ collection = "test", sortDirection = "sideways" })"#)
            .eval_async()
            .await;
        assert!(result.is_err());
        let err = result.unwrap_err().to_string();
        assert!(
            err.contains("invalid sortDirection"),
            "expected sortDirection error, got: {err}"
        );
    }

    #[test]
    fn cursor_round_trip() {
        let encoded = super::encode_cursor("2026-03-12T10:00:00Z", "at://did:plc:abc/col/rkey");
        let (ts, uri) = super::decode_cursor(&encoded).unwrap();
        assert_eq!(ts, "2026-03-12T10:00:00Z");
        assert_eq!(uri, "at://did:plc:abc/col/rkey");
    }

    #[test]
    fn decode_invalid_cursor_returns_none() {
        assert!(super::decode_cursor("not-valid-base64!!!").is_none());
    }

    #[test]
    fn decode_cursor_missing_pipe_returns_none() {
        use base64::{Engine, engine::general_purpose::STANDARD as BASE64};
        let encoded = BASE64.encode("no-pipe-here");
        assert!(super::decode_cursor(&encoded).is_none());
    }

    #[tokio::test]
    async fn query_accepts_valid_sort_direction() {
        let state = test_state();
        let lua = setup(&state);
        let result: Result<mlua::Value, _> = lua
            .load(r#"return db.query({ collection = "test", sortDirection = "asc" })"#)
            .eval_async()
            .await;
        // Should fail with a DB connection error, NOT a validation error
        assert!(result.is_err());
        let err = result.unwrap_err().to_string();
        assert!(
            !err.contains("invalid sortDirection"),
            "should have passed validation but got: {err}"
        );
    }
}
