mod procedure;
mod query;

use axum::Json;
use axum::body::Body;
use axum::extract::{ConnectInfo, FromRequestParts, Path, RawQuery, State};
use axum::http::StatusCode;
use axum::http::request::Parts;
use axum::response::Response;
use serde_json::Value;
use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};

use crate::AppState;
use crate::auth::Claims;
use crate::error::AppError;
use crate::lexicon::LexiconType;
use crate::rate_limit::CheckResult;
use crate::resolve::resolve_nsid_authority;

/// Parse a raw query string into a map where repeated keys become JSON arrays.
/// Single-value keys remain as JSON strings for backward compatibility.
fn parse_query_params(query: &str) -> HashMap<String, Value> {
    let mut multi: HashMap<String, Vec<String>> = HashMap::new();
    for pair in query.split('&') {
        if pair.is_empty() {
            continue;
        }
        let (key, value) = match pair.split_once('=') {
            Some((k, v)) => (
                urlencoding::decode(k).unwrap_or_default().into_owned(),
                urlencoding::decode(v).unwrap_or_default().into_owned(),
            ),
            None => (
                urlencoding::decode(pair).unwrap_or_default().into_owned(),
                String::new(),
            ),
        };
        multi.entry(key).or_default().push(value);
    }
    multi
        .into_iter()
        .map(|(k, v)| {
            if v.len() == 1 {
                (k, Value::String(v.into_iter().next().unwrap()))
            } else {
                (k, Value::Array(v.into_iter().map(Value::String).collect()))
            }
        })
        .collect()
}

/// Coerce query-param values from strings to their lexicon-declared types.
///
/// HTTP query params arrive as strings. Without this, Lua scripts receive
/// `"25"` (a string) for `params.limit`, which Postgres rejects when used
/// in LIMIT (`argument of LIMIT must be type bigint, not type text`).
fn coerce_params(params: &mut HashMap<String, Value>, parameters: &Value) {
    let properties = match parameters.get("properties").and_then(|p| p.as_object()) {
        Some(p) => p,
        None => return,
    };
    for (key, schema) in properties {
        let type_str = match schema.get("type").and_then(|t| t.as_str()) {
            Some(t) => t,
            None => continue,
        };
        let Some(val) = params.get(key) else {
            continue;
        };
        let Some(s) = val.as_str() else {
            continue;
        };
        match type_str {
            "integer" => {
                if let Ok(n) = s.parse::<i64>() {
                    params.insert(key.clone(), Value::Number(n.into()));
                }
            }
            "boolean" => match s {
                "true" | "1" => {
                    params.insert(key.clone(), Value::Bool(true));
                }
                "false" | "0" => {
                    params.insert(key.clone(), Value::Bool(false));
                }
                _ => {}
            },
            "number" => {
                if let Ok(n) = s.parse::<f64>()
                    && let Some(num) = serde_json::Number::from_f64(n)
                {
                    params.insert(key.clone(), Value::Number(num));
                }
            }
            _ => {}
        }
    }
}

/// Proxy an unrecognized XRPC method to its home AppView resolved via DNS.
async fn proxy_to_authority(
    state: &AppState,
    method: &str,
    query_string: &str,
    body: Option<&serde_json::Value>,
) -> Result<Response, AppError> {
    let (_did, pds_endpoint) = resolve_nsid_authority(&state.http, &state.config.plc_url, method)
        .await
        .map_err(|e| {
            AppError::BadGateway(format!("failed to resolve authority for {method}: {e}"))
        })?;

    let mut url = format!("{}/xrpc/{method}", pds_endpoint.trim_end_matches('/'),);
    if !query_string.is_empty() {
        url.push('?');
        url.push_str(query_string);
    }

    let request = if let Some(json_body) = body {
        state.http.post(&url).json(json_body)
    } else {
        state.http.get(&url)
    };

    let upstream = request
        .send()
        .await
        .map_err(|e| AppError::BadGateway(format!("upstream request failed for {method}: {e}")))?;

    let status =
        StatusCode::from_u16(upstream.status().as_u16()).unwrap_or(StatusCode::BAD_GATEWAY);

    let content_type = upstream
        .headers()
        .get(reqwest::header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("application/json")
        .to_string();

    let bytes = upstream.bytes().await.map_err(|e| {
        AppError::BadGateway(format!(
            "failed to read upstream response for {method}: {e}"
        ))
    })?;

    if !status.is_success() {
        return Err(AppError::PdsError(status, bytes));
    }

    Ok(Response::builder()
        .status(status)
        .header("content-type", content_type)
        .body(Body::from(bytes))
        .unwrap())
}

/// Extract client IP from X-Forwarded-For header or ConnectInfo.
fn extract_client_ip(parts: &Parts) -> Option<IpAddr> {
    if let Some(forwarded) = parts
        .headers
        .get("x-forwarded-for")
        .and_then(|v| v.to_str().ok())
        && let Some(first) = forwarded.split(',').next()
        && let Ok(ip) = first.trim().parse::<IpAddr>()
    {
        return Some(ip);
    }
    parts
        .extensions
        .get::<ConnectInfo<SocketAddr>>()
        .map(|ci| ci.0.ip())
}

/// Apply rate limit headers to a response.
fn apply_rate_limit_headers(response: &mut Response, remaining: u32, limit: u32, reset: u64) {
    let headers = response.headers_mut();
    headers.insert("RateLimit-Limit", limit.into());
    headers.insert("RateLimit-Remaining", remaining.into());
    headers.insert("RateLimit-Reset", reset.into());
}

/// Catch-all GET handler for XRPC queries.
pub async fn xrpc_get(
    State(state): State<AppState>,
    Path(method): Path<String>,
    RawQuery(raw_query): RawQuery,
    mut parts: Parts,
) -> Result<Response, AppError> {
    let raw_query = raw_query.unwrap_or_default();
    let mut params = parse_query_params(&raw_query);
    let client_ip = extract_client_ip(&parts);
    let claims = Claims::from_request_parts(&mut parts, &state).await.ok();

    // Rate limit check
    let rate_key = claims
        .as_ref()
        .map(|c| c.did().to_string())
        .unwrap_or_else(|| {
            client_ip
                .map(|ip| ip.to_string())
                .unwrap_or_else(|| "unknown".to_string())
        });

    let lexicon = state.lexicons.get(&method).await;

    // Determine token cost: per-NSID override → type default → 1
    let cost = if let Some(ref lex) = lexicon {
        lex.token_cost.unwrap_or_else(|| {
            let type_str = format!("{:?}", lex.lexicon_type).to_lowercase();
            state.rate_limiter.default_cost_for_type(&type_str)
        })
    } else {
        state.rate_limiter.default_cost_for_type("proxy")
    };

    let check = state.rate_limiter.check(&rate_key, cost, client_ip);

    match check {
        CheckResult::Limited {
            retry_after,
            limit,
            reset,
        } => {
            return Err(AppError::RateLimited {
                retry_after,
                limit,
                reset,
            });
        }
        CheckResult::Allowed { .. } | CheckResult::Disabled => {}
    }

    let lexicon = match lexicon {
        Some(l) => l,
        None => {
            let mut response = proxy_to_authority(&state, &method, &raw_query, None).await?;
            if let CheckResult::Allowed {
                remaining,
                limit,
                reset,
            } = check
            {
                apply_rate_limit_headers(&mut response, remaining, limit, reset);
            }
            return Ok(response);
        }
    };

    if lexicon.lexicon_type != LexiconType::Query {
        return Err(AppError::BadRequest(format!(
            "{method} is not a query endpoint"
        )));
    }

    if let Some(ref param_schema) = lexicon.parameters {
        coerce_params(&mut params, param_schema);
    }

    let mut response =
        query::handle_query(&state, &method, &params, &lexicon, claims.as_ref()).await?;
    if let CheckResult::Allowed {
        remaining,
        limit,
        reset,
    } = check
    {
        apply_rate_limit_headers(&mut response, remaining, limit, reset);
    }
    Ok(response)
}

/// Extract client IP from X-Forwarded-For header value.
fn ip_from_forwarded_for(value: Option<&str>) -> Option<IpAddr> {
    let forwarded = value?;
    let first = forwarded.split(',').next()?;
    first.trim().parse::<IpAddr>().ok()
}

/// Catch-all POST handler for XRPC procedures.
pub async fn xrpc_post(
    State(state): State<AppState>,
    Path(method): Path<String>,
    claims: Claims,
    headers: axum::http::HeaderMap,
    Json(body): Json<serde_json::Value>,
) -> Result<Response, AppError> {
    let client_ip =
        ip_from_forwarded_for(headers.get("x-forwarded-for").and_then(|v| v.to_str().ok()));
    let rate_key = claims.did().to_string();

    let lexicon = state.lexicons.get(&method).await;

    // Determine token cost: per-NSID override → type default → 1
    let cost = if let Some(ref lex) = lexicon {
        lex.token_cost.unwrap_or_else(|| {
            let type_str = format!("{:?}", lex.lexicon_type).to_lowercase();
            state.rate_limiter.default_cost_for_type(&type_str)
        })
    } else {
        state.rate_limiter.default_cost_for_type("proxy")
    };

    let check = state.rate_limiter.check(&rate_key, cost, client_ip);

    match check {
        CheckResult::Limited {
            retry_after,
            limit,
            reset,
        } => {
            return Err(AppError::RateLimited {
                retry_after,
                limit,
                reset,
            });
        }
        CheckResult::Allowed { .. } | CheckResult::Disabled => {}
    }

    let lexicon = match lexicon {
        Some(l) => l,
        None => {
            let mut response = proxy_to_authority(&state, &method, "", Some(&body)).await?;
            if let CheckResult::Allowed {
                remaining,
                limit,
                reset,
            } = check
            {
                apply_rate_limit_headers(&mut response, remaining, limit, reset);
            }
            return Ok(response);
        }
    };

    if lexicon.lexicon_type != LexiconType::Procedure {
        return Err(AppError::BadRequest(format!(
            "{method} is not a procedure endpoint"
        )));
    }

    let mut response =
        procedure::handle_procedure(&state, &method, &claims, &body, &lexicon).await?;
    if let CheckResult::Allowed {
        remaining,
        limit,
        reset,
    } = check
    {
        apply_rate_limit_headers(&mut response, remaining, limit, reset);
    }
    Ok(response)
}
