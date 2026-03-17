use mlua::{Lua, Result as LuaResult};
use reqwest::Method;
use std::sync::Arc;

use crate::AppState;

/// Register the `http` table with async HTTP request functions.
pub fn register_http_api(lua: &Lua, state: Arc<AppState>) -> LuaResult<()> {
    let http_table = lua.create_table()?;

    let methods = [
        ("get", Method::GET),
        ("post", Method::POST),
        ("put", Method::PUT),
        ("patch", Method::PATCH),
        ("delete", Method::DELETE),
        ("head", Method::HEAD),
    ];

    for (name, method) in methods {
        let state_clone = state.clone();
        let func =
            lua.create_async_function(move |lua, (url, opts): (String, Option<mlua::Table>)| {
                let state = state_clone.clone();
                let method = method.clone();
                async move {
                    let mut builder = state.http.request(method.clone(), &url);

                    if let Some(ref opts) = opts {
                        if let Ok(headers_table) = opts.get::<mlua::Table>("headers") {
                            for pair in headers_table.pairs::<String, String>() {
                                let (key, value) = pair?;
                                builder = builder.header(key, value);
                            }
                        }

                        if method != Method::GET
                            && method != Method::HEAD
                            && let Ok(body) = opts.get::<String>("body")
                        {
                            builder = builder.body(body);
                        }
                    }

                    let response = builder
                        .send()
                        .await
                        .map_err(|e| mlua::Error::runtime(format!("HTTP request failed: {e}")))?;

                    let status = response.status().as_u16();

                    let headers_table = lua.create_table()?;
                    for (key, value) in response.headers() {
                        if let Ok(v) = value.to_str() {
                            headers_table.set(key.as_str().to_lowercase(), v.to_string())?;
                        }
                    }

                    let body = if method == Method::HEAD {
                        String::new()
                    } else {
                        response.text().await.map_err(|e| {
                            mlua::Error::runtime(format!("HTTP read body failed: {e}"))
                        })?
                    };

                    let result = lua.create_table()?;
                    result.set("status", status)?;
                    result.set("body", body)?;
                    result.set("headers", headers_table)?;

                    Ok(mlua::Value::Table(result))
                }
            })?;
        http_table.set(name, func)?;
    }

    lua.globals().set("http", http_table)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::Config;
    use crate::lexicon::LexiconRegistry;
    use tokio::sync::watch;

    fn test_state() -> AppState {
        let config = Config {
            host: "127.0.0.1".into(),
            port: 3000,
            database_url: String::new(),
            aip_url: String::new(),
            aip_public_url: String::new(),
            tap_url: String::new(),
            tap_admin_password: None,
            relay_url: String::new(),
            plc_url: String::new(),
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
                },
                std::collections::HashMap::new(),
                vec![],
            ),
        }
    }

    fn setup(state: &AppState) -> Lua {
        let lua = Lua::new();
        register_http_api(&lua, Arc::new(state.clone())).unwrap();
        lua
    }

    #[tokio::test]
    async fn get_returns_status_and_body() {
        let mock = wiremock::MockServer::start().await;
        wiremock::Mock::given(wiremock::matchers::method("GET"))
            .and(wiremock::matchers::path("/test"))
            .respond_with(wiremock::ResponseTemplate::new(200).set_body_string("hello"))
            .mount(&mock)
            .await;

        let state = test_state();
        let lua = setup(&state);
        let chunk = format!(r#"return http.get("{}/test")"#, mock.uri());
        let result: mlua::Table = lua.load(chunk).eval_async().await.unwrap();
        assert_eq!(result.get::<u16>("status").unwrap(), 200);
        assert_eq!(result.get::<String>("body").unwrap(), "hello");
    }

    #[tokio::test]
    async fn get_returns_headers() {
        let mock = wiremock::MockServer::start().await;
        wiremock::Mock::given(wiremock::matchers::method("GET"))
            .and(wiremock::matchers::path("/h"))
            .respond_with(
                wiremock::ResponseTemplate::new(200)
                    .insert_header("X-Custom", "test-value")
                    .set_body_string(""),
            )
            .mount(&mock)
            .await;

        let state = test_state();
        let lua = setup(&state);
        let chunk = format!(r#"return http.get("{}/h")"#, mock.uri());
        let result: mlua::Table = lua.load(chunk).eval_async().await.unwrap();
        let headers: mlua::Table = result.get("headers").unwrap();
        assert_eq!(headers.get::<String>("x-custom").unwrap(), "test-value");
    }

    #[tokio::test]
    async fn post_sends_body_and_headers() {
        let mock = wiremock::MockServer::start().await;
        wiremock::Mock::given(wiremock::matchers::method("POST"))
            .and(wiremock::matchers::path("/post"))
            .and(wiremock::matchers::header(
                "content-type",
                "application/json",
            ))
            .and(wiremock::matchers::body_string(r#"{"k":"v"}"#))
            .respond_with(wiremock::ResponseTemplate::new(201).set_body_string("created"))
            .mount(&mock)
            .await;

        let state = test_state();
        let lua = setup(&state);
        let chunk = format!(
            r#"return http.post("{}/post", {{
                body = '{{"k":"v"}}',
                headers = {{ ["content-type"] = "application/json" }}
            }})"#,
            mock.uri()
        );
        let result: mlua::Table = lua.load(chunk).eval_async().await.unwrap();
        assert_eq!(result.get::<u16>("status").unwrap(), 201);
        assert_eq!(result.get::<String>("body").unwrap(), "created");
    }

    #[tokio::test]
    async fn head_returns_empty_body() {
        let mock = wiremock::MockServer::start().await;
        wiremock::Mock::given(wiremock::matchers::method("HEAD"))
            .and(wiremock::matchers::path("/head"))
            .respond_with(wiremock::ResponseTemplate::new(204))
            .mount(&mock)
            .await;

        let state = test_state();
        let lua = setup(&state);
        let chunk = format!(r#"return http.head("{}/head")"#, mock.uri());
        let result: mlua::Table = lua.load(chunk).eval_async().await.unwrap();
        assert_eq!(result.get::<u16>("status").unwrap(), 204);
        assert_eq!(result.get::<String>("body").unwrap(), "");
    }

    #[tokio::test]
    async fn put_sends_body() {
        let mock = wiremock::MockServer::start().await;
        wiremock::Mock::given(wiremock::matchers::method("PUT"))
            .and(wiremock::matchers::path("/put"))
            .and(wiremock::matchers::body_string("updated"))
            .respond_with(wiremock::ResponseTemplate::new(200).set_body_string("ok"))
            .mount(&mock)
            .await;

        let state = test_state();
        let lua = setup(&state);
        let chunk = format!(
            r#"return http.put("{}/put", {{ body = "updated" }})"#,
            mock.uri()
        );
        let result: mlua::Table = lua.load(chunk).eval_async().await.unwrap();
        assert_eq!(result.get::<u16>("status").unwrap(), 200);
    }

    #[tokio::test]
    async fn delete_works() {
        let mock = wiremock::MockServer::start().await;
        wiremock::Mock::given(wiremock::matchers::method("DELETE"))
            .and(wiremock::matchers::path("/del"))
            .respond_with(wiremock::ResponseTemplate::new(204).set_body_string(""))
            .mount(&mock)
            .await;

        let state = test_state();
        let lua = setup(&state);
        let chunk = format!(r#"return http.delete("{}/del")"#, mock.uri());
        let result: mlua::Table = lua.load(chunk).eval_async().await.unwrap();
        assert_eq!(result.get::<u16>("status").unwrap(), 204);
    }

    #[tokio::test]
    async fn patch_sends_body() {
        let mock = wiremock::MockServer::start().await;
        wiremock::Mock::given(wiremock::matchers::method("PATCH"))
            .and(wiremock::matchers::path("/patch"))
            .and(wiremock::matchers::body_string("patched"))
            .respond_with(wiremock::ResponseTemplate::new(200).set_body_string("ok"))
            .mount(&mock)
            .await;

        let state = test_state();
        let lua = setup(&state);
        let chunk = format!(
            r#"return http.patch("{}/patch", {{ body = "patched" }})"#,
            mock.uri()
        );
        let result: mlua::Table = lua.load(chunk).eval_async().await.unwrap();
        assert_eq!(result.get::<u16>("status").unwrap(), 200);
    }

    #[tokio::test]
    async fn get_without_opts_works() {
        let mock = wiremock::MockServer::start().await;
        wiremock::Mock::given(wiremock::matchers::method("GET"))
            .and(wiremock::matchers::path("/simple"))
            .respond_with(wiremock::ResponseTemplate::new(200).set_body_string("ok"))
            .mount(&mock)
            .await;

        let state = test_state();
        let lua = setup(&state);
        let chunk = format!(r#"return http.get("{}/simple")"#, mock.uri());
        let result: mlua::Table = lua.load(chunk).eval_async().await.unwrap();
        assert_eq!(result.get::<u16>("status").unwrap(), 200);
        assert_eq!(result.get::<String>("body").unwrap(), "ok");
    }

    #[tokio::test]
    async fn invalid_url_returns_error() {
        let state = test_state();
        let lua = setup(&state);
        let result: Result<mlua::Table, _> = lua
            .load(r#"return http.get("http://0.0.0.0:1/nope")"#)
            .eval_async()
            .await;
        assert!(result.is_err());
    }
}
