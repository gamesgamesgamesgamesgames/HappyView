use mlua::{Lua, Result as LuaResult};
use std::sync::Arc;

use crate::AppState;
use crate::profile;

/// Register the `atproto` table with AT Protocol utility functions.
pub fn register_atproto_api(lua: &Lua, state: Arc<AppState>) -> LuaResult<()> {
    let atproto_table = lua.create_table()?;

    let state_clone = state.clone();
    let resolve_fn = lua.create_async_function(move |_lua, did: String| {
        let state = state_clone.clone();
        async move {
            let result =
                profile::resolve_pds_endpoint(&state.http, &state.config.plc_url, &did).await;

            match result {
                Ok(endpoint) => Ok(Some(endpoint)),
                Err(_) => Ok(None),
            }
        }
    })?;

    atproto_table.set("resolve_service_endpoint", resolve_fn)?;

    // get_labels(uri) -> array of { src, uri, val, cts }
    let state_clone = state.clone();
    let get_labels_fn = lua.create_async_function(move |lua, uri: String| {
        let state = state_clone.clone();
        async move {
            // Query external labels from the labels table.
            let rows: Vec<(String, String, String, chrono::DateTime<chrono::Utc>)> =
                sqlx::query_as(
                    "SELECT src, uri, val, cts FROM labels WHERE uri = $1 AND (exp IS NULL OR exp > NOW())",
                )
                .bind(&uri)
                .fetch_all(&state.db)
                .await
                .map_err(|e| mlua::Error::runtime(format!("label query failed: {e}")))?;

            let result = lua.create_table()?;
            let mut idx = 1;

            for (src, label_uri, val, cts) in &rows {
                let label = lua.create_table()?;
                label.set("src", src.as_str())?;
                label.set("uri", label_uri.as_str())?;
                label.set("val", val.as_str())?;
                label.set("cts", cts.to_rfc3339())?;
                result.set(idx, label)?;
                idx += 1;
            }

            // Check for self-labels in the record itself.
            let record: Option<(String, serde_json::Value)> = sqlx::query_as(
                "SELECT did, record FROM records WHERE uri = $1",
            )
            .bind(&uri)
            .fetch_optional(&state.db)
            .await
            .map_err(|e| mlua::Error::runtime(format!("record query failed: {e}")))?;

            if let Some((did, record)) = record
                && let Some(labels) = record.get("labels")
                && let Some(values) = labels.get("values")
                && let Some(arr) = values.as_array()
            {
                for item in arr {
                    if let Some(val) = item.get("val").and_then(|v| v.as_str()) {
                        let label = lua.create_table()?;
                        label.set("src", did.as_str())?;
                        label.set("uri", uri.as_str())?;
                        label.set("val", val)?;
                        label.set("cts", "")?;
                        result.set(idx, label)?;
                        idx += 1;
                    }
                }
            }

            Ok(mlua::Value::Table(result))
        }
    })?;
    atproto_table.set("get_labels", get_labels_fn)?;

    // get_labels_batch(uris) -> table keyed by URI
    let state_clone = state.clone();
    let get_labels_batch_fn = lua.create_async_function(move |lua, uris: mlua::Table| {
        let state = state_clone.clone();
        async move {
            // Collect URIs from the Lua table.
            let uri_list: Vec<String> = uris
                .sequence_values::<String>()
                .collect::<Result<Vec<_>, _>>()?;

            // Query all labels for all URIs at once.
            let rows: Vec<(String, String, String, chrono::DateTime<chrono::Utc>)> =
                sqlx::query_as(
                    "SELECT src, uri, val, cts FROM labels WHERE uri = ANY($1) AND (exp IS NULL OR exp > NOW())",
                )
                .bind(&uri_list)
                .fetch_all(&state.db)
                .await
                .map_err(|e| mlua::Error::runtime(format!("label batch query failed: {e}")))?;

            // Query records for self-labels.
            let records: Vec<(String, String, serde_json::Value)> = sqlx::query_as(
                "SELECT uri, did, record FROM records WHERE uri = ANY($1)",
            )
            .bind(&uri_list)
            .fetch_all(&state.db)
            .await
            .map_err(|e| mlua::Error::runtime(format!("record batch query failed: {e}")))?;

            // Build result table keyed by URI.
            let result = lua.create_table()?;

            // Initialize empty arrays for each URI.
            let mut counters: std::collections::HashMap<String, i32> = std::collections::HashMap::new();
            for uri in &uri_list {
                result.set(uri.as_str(), lua.create_table()?)?;
                counters.insert(uri.clone(), 1);
            }

            // Add external labels.
            for (src, uri, val, cts) in &rows {
                let label = lua.create_table()?;
                label.set("src", src.as_str())?;
                label.set("uri", uri.as_str())?;
                label.set("val", val.as_str())?;
                label.set("cts", cts.to_rfc3339())?;

                let uri_table: mlua::Table = result.get(uri.as_str())?;
                let idx = counters.get(uri).copied().unwrap_or(1);
                uri_table.set(idx, label)?;
                counters.insert(uri.clone(), idx + 1);
            }

            // Add self-labels from records.
            for (uri, did, record) in &records {
                if let Some(labels) = record.get("labels")
                    && let Some(values) = labels.get("values")
                    && let Some(arr) = values.as_array()
                {
                    for item in arr {
                        if let Some(val) = item.get("val").and_then(|v| v.as_str()) {
                            let label = lua.create_table()?;
                            label.set("src", did.as_str())?;
                            label.set("uri", uri.as_str())?;
                            label.set("val", val)?;
                            label.set("cts", "")?;

                            let uri_table: mlua::Table = result.get(uri.as_str())?;
                            let idx = counters.get(uri).copied().unwrap_or(1);
                            uri_table.set(idx, label)?;
                            counters.insert(uri.clone(), idx + 1);
                        }
                    }
                }
            }

            Ok(mlua::Value::Table(result))
        }
    })?;
    atproto_table.set("get_labels_batch", get_labels_batch_fn)?;

    lua.globals().set("atproto", atproto_table)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::Config;
    use crate::lexicon::LexiconRegistry;
    use tokio::sync::watch;

    fn test_state_with_plc(plc_url: &str) -> AppState {
        let config = Config {
            host: "127.0.0.1".into(),
            port: 3000,
            database_url: String::new(),
            aip_url: String::new(),
            aip_public_url: String::new(),
            tap_url: String::new(),
            tap_admin_password: None,
            relay_url: String::new(),
            plc_url: plc_url.to_string(),
            static_dir: String::new(),
            event_log_retention_days: 30,
        };
        let (tx, _) = watch::channel(vec![]);
        let (labeler_tx, _) = watch::channel(());
        AppState {
            config,
            http: reqwest::Client::new(),
            db: sqlx::PgPool::connect_lazy("postgres://localhost/fake").unwrap(),
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
        }
    }

    #[tokio::test]
    async fn resolve_service_endpoint_returns_endpoint() {
        let mock = wiremock::MockServer::start().await;

        let did_doc = serde_json::json!({
            "id": "did:plc:test123",
            "alsoKnownAs": ["at://test.example.com"],
            "service": [{
                "id": "#atproto_pds",
                "type": "AtprotoPersonalDataServer",
                "serviceEndpoint": "https://pds.example.com"
            }]
        });

        wiremock::Mock::given(wiremock::matchers::method("GET"))
            .and(wiremock::matchers::path("/did:plc:test123"))
            .respond_with(wiremock::ResponseTemplate::new(200).set_body_json(&did_doc))
            .mount(&mock)
            .await;

        let state = test_state_with_plc(&mock.uri());
        let lua = mlua::Lua::new();
        register_atproto_api(&lua, Arc::new(state)).unwrap();

        let chunk = r#"return atproto.resolve_service_endpoint("did:plc:test123")"#;
        let result: String = lua.load(chunk).eval_async().await.unwrap();
        assert_eq!(result, "https://pds.example.com");
    }

    #[tokio::test]
    async fn resolve_service_endpoint_returns_nil_on_failure() {
        let mock = wiremock::MockServer::start().await;

        wiremock::Mock::given(wiremock::matchers::method("GET"))
            .and(wiremock::matchers::path("/did:plc:unknown"))
            .respond_with(wiremock::ResponseTemplate::new(404))
            .mount(&mock)
            .await;

        let state = test_state_with_plc(&mock.uri());
        let lua = mlua::Lua::new();
        register_atproto_api(&lua, Arc::new(state)).unwrap();

        let chunk = r#"return atproto.resolve_service_endpoint("did:plc:unknown")"#;
        let result: mlua::Value = lua.load(chunk).eval_async().await.unwrap();
        assert!(matches!(result, mlua::Value::Nil));
    }

    #[tokio::test]
    async fn resolve_did_web() {
        let mock = wiremock::MockServer::start().await;

        let state = test_state_with_plc(&mock.uri());
        let lua = mlua::Lua::new();
        register_atproto_api(&lua, Arc::new(state)).unwrap();

        let chunk = r#"return type(atproto.resolve_service_endpoint)"#;
        let result: String = lua.load(chunk).eval_async().await.unwrap();
        assert_eq!(result, "function");
    }
}
