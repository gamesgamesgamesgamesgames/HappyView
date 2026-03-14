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
        AppState {
            config,
            http: reqwest::Client::new(),
            db: sqlx::PgPool::connect_lazy("postgres://localhost/fake").unwrap(),
            lexicons: LexiconRegistry::new(),
            collections_tx: tx,
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
