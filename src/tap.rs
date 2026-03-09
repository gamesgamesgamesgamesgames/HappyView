use futures_util::{SinkExt, StreamExt};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use tokio::sync::watch;
use tokio_tungstenite::tungstenite::Message;
use tokio_tungstenite::tungstenite::client::IntoClientRequest;

use crate::AppState;
use crate::event_log::{EventLog, Severity, log_event};
use crate::lexicon::{LexiconType, ParsedLexicon, ProcedureAction};

// ---------------------------------------------------------------------------
// Tap event types (matches Tap's outbox JSON format)
// ---------------------------------------------------------------------------

#[derive(Deserialize)]
struct TapEvent {
    id: u64,
    #[serde(rename = "type")]
    event_type: String,
    record: Option<TapRecordEvent>,
    identity: Option<TapIdentityEvent>,
}

#[derive(Deserialize)]
struct TapRecordEvent {
    did: String,
    collection: String,
    rkey: String,
    action: String,
    record: Option<Value>,
    cid: Option<String>,
    #[allow(dead_code)]
    live: Option<bool>,
}

#[derive(Deserialize)]
#[allow(dead_code)]
struct TapIdentityEvent {
    did: String,
    handle: Option<String>,
    #[serde(rename = "isActive")]
    is_active: Option<bool>,
    status: Option<String>,
}

// ---------------------------------------------------------------------------
// Tap HTTP client helpers
// ---------------------------------------------------------------------------

async fn tap_put(
    http: &reqwest::Client,
    tap_url: &str,
    path: &str,
    password: Option<&str>,
    body: &Value,
) -> Result<(), String> {
    let url = format!("{}{}", tap_url.trim_end_matches('/'), path);
    let mut req = http.put(&url).json(body);
    if let Some(pw) = password {
        req = req.basic_auth("admin", Some(pw));
    }
    let resp = req
        .send()
        .await
        .map_err(|e| format!("tap HTTP request failed: {e}"))?;
    if !resp.status().is_success() {
        let status = resp.status();
        let body = resp.text().await.unwrap_or_default();
        return Err(format!("tap returned {status}: {body}"));
    }
    Ok(())
}

async fn tap_post(
    http: &reqwest::Client,
    tap_url: &str,
    path: &str,
    password: Option<&str>,
    body: &Value,
) -> Result<(), String> {
    let url = format!("{}{}", tap_url.trim_end_matches('/'), path);
    let mut req = http.post(&url).json(body);
    if let Some(pw) = password {
        req = req.basic_auth("admin", Some(pw));
    }
    let resp = req
        .send()
        .await
        .map_err(|e| format!("tap HTTP request failed: {e}"))?;
    if !resp.status().is_success() {
        let status = resp.status();
        let body = resp.text().await.unwrap_or_default();
        return Err(format!("tap returned {status}: {body}"));
    }
    Ok(())
}

async fn tap_get<T: serde::de::DeserializeOwned>(
    http: &reqwest::Client,
    tap_url: &str,
    path: &str,
    password: Option<&str>,
) -> Result<T, String> {
    let url = format!("{}{}", tap_url.trim_end_matches('/'), path);
    let mut req = http.get(&url);
    if let Some(pw) = password {
        req = req.basic_auth("admin", Some(pw));
    }
    let resp = req
        .send()
        .await
        .map_err(|e| format!("tap HTTP request failed: {e}"))?;
    if !resp.status().is_success() {
        let status = resp.status();
        let body = resp.text().await.unwrap_or_default();
        return Err(format!("tap returned {status}: {body}"));
    }
    resp.json::<T>()
        .await
        .map_err(|e| format!("failed to parse tap response: {e}"))
}

// ---------------------------------------------------------------------------
// Tap stats
// ---------------------------------------------------------------------------

#[derive(Serialize)]
pub struct TapStats {
    pub repo_count: u64,
    pub record_count: u64,
    pub outbox_buffer: u64,
}

#[derive(Deserialize)]
struct RepoCountResponse {
    repo_count: u64,
}

#[derive(Deserialize)]
struct RecordCountResponse {
    record_count: u64,
}

#[derive(Deserialize)]
struct OutboxBufferResponse {
    outbox_buffer: u64,
}

/// Fetch aggregate stats from Tap's monitoring endpoints in parallel.
pub async fn get_stats(
    http: &reqwest::Client,
    tap_url: &str,
    tap_admin_password: Option<&str>,
) -> Result<TapStats, String> {
    let (repo, record, outbox) = tokio::try_join!(
        tap_get::<RepoCountResponse>(http, tap_url, "/stats/repo-count", tap_admin_password),
        tap_get::<RecordCountResponse>(http, tap_url, "/stats/record-count", tap_admin_password),
        tap_get::<OutboxBufferResponse>(http, tap_url, "/stats/outbox-buffer", tap_admin_password),
    )?;

    Ok(TapStats {
        repo_count: repo.repo_count,
        record_count: record.record_count,
        outbox_buffer: outbox.outbox_buffer,
    })
}

/// Sync Tap's collection filters and signal collections with HappyView's
/// current record collections.
pub async fn sync_collections(
    http: &reqwest::Client,
    tap_url: &str,
    tap_admin_password: Option<&str>,
    collections: &[String],
) -> Result<(), String> {
    let body = serde_json::json!({ "collections": collections });
    tap_put(
        http,
        tap_url,
        "/collection-filters",
        tap_admin_password,
        &body,
    )
    .await?;
    tap_put(
        http,
        tap_url,
        "/signal-collections",
        tap_admin_password,
        &body,
    )
    .await?;
    Ok(())
}

/// Add repos to Tap for backfill via POST /repos/add.
pub async fn add_repos(
    http: &reqwest::Client,
    tap_url: &str,
    tap_admin_password: Option<&str>,
    dids: &[String],
) -> Result<(), String> {
    let body = serde_json::json!({ "dids": dids });
    tap_post(http, tap_url, "/repos/add", tap_admin_password, &body).await
}

/// Remove repos from Tap via POST /repos/remove, clearing their cached state
/// so a subsequent add triggers a fresh resync.
pub async fn remove_repos(
    http: &reqwest::Client,
    tap_url: &str,
    tap_admin_password: Option<&str>,
    dids: &[String],
) -> Result<(), String> {
    let body = serde_json::json!({ "dids": dids });
    tap_post(http, tap_url, "/repos/remove", tap_admin_password, &body).await
}

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

/// The static collection we always include for lexicon schema updates.
const LEXICON_SCHEMA_COLLECTION: &str = "com.atproto.lexicon.schema";

/// Spawn a background task that connects to Tap's WebSocket channel and
/// processes record + identity events. Replaces both jetstream and backfill.
///
/// When the collection list changes (via `collections_rx`), the task syncs
/// the updated filters to Tap's HTTP API.
pub fn spawn(state: AppState, mut collections_rx: watch::Receiver<Vec<String>>) {
    tokio::spawn(async move {
        loop {
            // Build WebSocket URL from HTTP URL.
            let ws_url = build_ws_url(&state.config.tap_url);

            match run(&state, &ws_url, &mut collections_rx).await {
                Ok(()) => {
                    tracing::info!("tap reconnecting due to collection change");
                }
                Err(e) => {
                    tracing::warn!("tap disconnected: {e}");
                    tokio::time::sleep(std::time::Duration::from_secs(2)).await;
                    tracing::info!("reconnecting to tap...");
                }
            }
        }
    });
}

fn build_ws_url(tap_url: &str) -> String {
    let base = tap_url.trim_end_matches('/');
    let ws_base = if let Some(rest) = base.strip_prefix("https://") {
        format!("wss://{rest}")
    } else if let Some(rest) = base.strip_prefix("http://") {
        format!("ws://{rest}")
    } else {
        format!("ws://{base}")
    };
    format!("{ws_base}/channel")
}

// ---------------------------------------------------------------------------
// Connection loop
// ---------------------------------------------------------------------------

async fn run(
    state: &AppState,
    ws_url: &str,
    collections_rx: &mut watch::Receiver<Vec<String>>,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let db = &state.db;
    let http = &state.http;
    let tap_url = &state.config.tap_url;
    let tap_admin_password = state.config.tap_admin_password.as_deref();

    tracing::info!(url = %ws_url, "connecting to tap");

    let mut request = ws_url.to_string().into_client_request()?;
    if let Some(pw) = tap_admin_password {
        use base64::Engine;
        let encoded = base64::engine::general_purpose::STANDARD.encode(format!("admin:{pw}"));
        request
            .headers_mut()
            .insert("Authorization", format!("Basic {encoded}").parse().unwrap());
    }

    let (ws, _): (
        tokio_tungstenite::WebSocketStream<
            tokio_tungstenite::MaybeTlsStream<tokio::net::TcpStream>,
        >,
        _,
    ) = tokio_tungstenite::connect_async(request).await?;
    tracing::info!("connected to tap");

    // Re-sync collection filters on every (re)connect so Tap knows which
    // collections to track, even if Tap was restarted since the initial sync.
    {
        let collections = collections_rx.borrow().clone();
        let mut wanted = collections;
        if !wanted.contains(&LEXICON_SCHEMA_COLLECTION.to_string()) {
            wanted.push(LEXICON_SCHEMA_COLLECTION.to_string());
        }
        if let Err(e) = sync_collections(http, tap_url, tap_admin_password, &wanted).await {
            tracing::warn!("failed to sync collections to tap on reconnect: {e}");
        }
    }

    log_event(
        db,
        EventLog {
            event_type: "tap.connected".to_string(),
            severity: Severity::Info,
            actor_did: None,
            subject: None,
            detail: serde_json::json!({ "url": ws_url }),
        },
    )
    .await;

    let (mut write, mut read) = ws.split();

    loop {
        tokio::select! {
            msg = read.next() => {
                let msg = match msg {
                    Some(Ok(m)) => m,
                    Some(Err(e)) => return Err(e.into()),
                    None => break,
                };

                let text = match msg {
                    Message::Text(t) => t,
                    Message::Close(_) => break,
                    _ => continue,
                };

                let event: TapEvent = match serde_json::from_str(&text) {
                    Ok(e) => e,
                    Err(e) => {
                        tracing::debug!("skipping unparseable tap event: {e}");
                        continue;
                    }
                };

                let event_id = event.id;

                match event.event_type.as_str() {
                    "record" => {
                        if let Some(record) = event.record {
                            handle_record_event(state, &record).await;
                        }
                    }
                    "identity" => {
                        if let Some(identity) = event.identity {
                            tracing::debug!(
                                did = %identity.did,
                                handle = ?identity.handle,
                                "received identity event from tap"
                            );
                        }
                    }
                    other => {
                        tracing::debug!(event_type = %other, "unknown tap event type");
                    }
                }

                // Ack the event.
                let ack = serde_json::json!({ "type": "ack", "id": event_id });
                if let Err(e) = write.send(Message::Text(ack.to_string().into())).await {
                    tracing::warn!("failed to send ack: {e}");
                    return Err(e.into());
                }
            }
            // If the collection list changes, sync to Tap and continue.
            _ = collections_rx.changed() => {
                let collections = collections_rx.borrow_and_update().clone();
                tracing::info!(?collections, "collection filter changed, syncing to tap");

                // Always include the lexicon schema collection.
                let mut wanted = collections;
                if !wanted.contains(&LEXICON_SCHEMA_COLLECTION.to_string()) {
                    wanted.push(LEXICON_SCHEMA_COLLECTION.to_string());
                }

                if let Err(e) = sync_collections(http, tap_url, tap_admin_password, &wanted).await {
                    tracing::warn!("failed to sync collections to tap: {e}");
                }
            }
        }
    }

    log_event(
        db,
        EventLog {
            event_type: "tap.disconnected".to_string(),
            severity: Severity::Warn,
            actor_did: None,
            subject: None,
            detail: serde_json::json!({ "reason": "connection closed" }),
        },
    )
    .await;

    Ok(())
}

// ---------------------------------------------------------------------------
// Record event handler
// ---------------------------------------------------------------------------

async fn handle_record_event(state: &AppState, record: &TapRecordEvent) {
    let db = &state.db;
    let lexicons = &state.lexicons;

    let uri = format!("at://{}/{}/{}", record.did, record.collection, record.rkey,);

    // Handle lexicon schema events for tracked network lexicons.
    if record.collection == LEXICON_SCHEMA_COLLECTION {
        handle_lexicon_schema_event(state, &record.did, record).await;
        return;
    }

    // Skip records whose collection is not tracked by a registered record-type lexicon.
    let is_tracked = lexicons
        .get(&record.collection)
        .await
        .is_some_and(|lex| lex.lexicon_type == LexiconType::Record);

    if !is_tracked {
        tracing::debug!(
            collection = %record.collection,
            "skipping record for untracked collection"
        );
        return;
    }

    match record.action.as_str() {
        "create" | "update" => {
            let rec = match &record.record {
                Some(r) => r,
                None => return,
            };
            let cid = record.cid.as_deref().unwrap_or_default();

            // Run index hook before storing, if configured. The hook's return
            // value determines what (if anything) gets written to the DB.
            let rec_to_store =
                if let Some(script) = state.lexicons.get_index_hook(&record.collection).await {
                    let hook_result = crate::lua::execute_hook_script(&crate::lua::HookEvent {
                        state,
                        lexicon_id: &record.collection,
                        script: &script,
                        action: &record.action,
                        uri: &uri,
                        did: &record.did,
                        collection: &record.collection,
                        rkey: &record.rkey,
                        record: Some(rec),
                    })
                    .await;

                    match hook_result {
                        None => {
                            // Hook returned nil — skip indexing this record.
                            log_event(
                                db,
                                EventLog {
                                    event_type: "record.skipped".to_string(),
                                    severity: Severity::Info,
                                    actor_did: None,
                                    subject: Some(uri.clone()),
                                    detail: serde_json::json!({
                                        "collection": record.collection,
                                        "did": record.did,
                                        "rkey": record.rkey,
                                        "reason": "hook returned nil",
                                    }),
                                },
                            )
                            .await;
                            return;
                        }
                        Some(v) => v,
                    }
                } else {
                    // No hook — store the original record as-is.
                    rec.clone()
                };

            match sqlx::query(
                r#"
                INSERT INTO records (uri, did, collection, rkey, record, cid, indexed_at)
                VALUES ($1, $2, $3, $4, $5, $6, NOW())
                ON CONFLICT (uri) DO UPDATE
                    SET record = EXCLUDED.record,
                        cid = EXCLUDED.cid,
                        indexed_at = NOW()
                "#,
            )
            .bind(&uri)
            .bind(&record.did)
            .bind(&record.collection)
            .bind(&record.rkey)
            .bind(&rec_to_store)
            .bind(cid)
            .execute(db)
            .await
            {
                Ok(_) => {
                    log_event(
                        db,
                        EventLog {
                            event_type: "record.created".to_string(),
                            severity: Severity::Info,
                            actor_did: None,
                            subject: Some(uri.clone()),
                            detail: serde_json::json!({
                                "collection": record.collection,
                                "did": record.did,
                                "rkey": record.rkey,
                            }),
                        },
                    )
                    .await;
                }
                Err(e) => {
                    tracing::warn!(uri = %uri, "failed to upsert record: {e}");
                    log_event(
                        db,
                        EventLog {
                            event_type: "record.created".to_string(),
                            severity: Severity::Error,
                            actor_did: None,
                            subject: Some(uri.clone()),
                            detail: serde_json::json!({
                                "collection": record.collection,
                                "did": record.did,
                                "rkey": record.rkey,
                                "error": e.to_string(),
                            }),
                        },
                    )
                    .await;
                }
            }
        }
        "delete" => {
            // Run index hook before deleting, if configured.
            if let Some(script) = state.lexicons.get_index_hook(&record.collection).await {
                let hook_result = crate::lua::execute_hook_script(&crate::lua::HookEvent {
                    state,
                    lexicon_id: &record.collection,
                    script: &script,
                    action: "delete",
                    uri: &uri,
                    did: &record.did,
                    collection: &record.collection,
                    rkey: &record.rkey,
                    record: None,
                })
                .await;

                if hook_result.is_none() {
                    // Hook returned nil — skip the delete.
                    log_event(
                        db,
                        EventLog {
                            event_type: "record.skipped".to_string(),
                            severity: Severity::Info,
                            actor_did: None,
                            subject: Some(uri.clone()),
                            detail: serde_json::json!({
                                "collection": record.collection,
                                "did": record.did,
                                "rkey": record.rkey,
                                "reason": "hook returned nil",
                            }),
                        },
                    )
                    .await;
                    return;
                }
            }

            match sqlx::query("DELETE FROM records WHERE uri = $1")
                .bind(&uri)
                .execute(db)
                .await
            {
                Ok(_) => {
                    log_event(
                        db,
                        EventLog {
                            event_type: "record.deleted".to_string(),
                            severity: Severity::Info,
                            actor_did: None,
                            subject: Some(uri.clone()),
                            detail: serde_json::json!({
                                "collection": record.collection,
                                "did": record.did,
                                "rkey": record.rkey,
                            }),
                        },
                    )
                    .await;
                }
                Err(e) => {
                    tracing::warn!(uri = %uri, "failed to delete record: {e}");
                    log_event(
                        db,
                        EventLog {
                            event_type: "record.deleted".to_string(),
                            severity: Severity::Error,
                            actor_did: None,
                            subject: Some(uri.clone()),
                            detail: serde_json::json!({
                                "collection": record.collection,
                                "did": record.did,
                                "rkey": record.rkey,
                                "error": e.to_string(),
                            }),
                        },
                    )
                    .await;
                }
            }
        }
        _ => {}
    }
}

// ---------------------------------------------------------------------------
// Lexicon schema event handler
// ---------------------------------------------------------------------------

/// Handle a `com.atproto.lexicon.schema` record event for tracked network lexicons.
async fn handle_lexicon_schema_event(state: &AppState, did: &str, record: &TapRecordEvent) {
    let db = &state.db;
    let lexicons = &state.lexicons;
    let collections_tx = &state.collections_tx;
    let nsid = &record.rkey;

    // Check if this NSID is one we're tracking and the DID matches the authority.
    let tracked: Option<(Option<String>,)> = sqlx::query_as(
        "SELECT target_collection FROM lexicons WHERE id = $1 AND source = 'network' AND authority_did = $2",
    )
    .bind(nsid)
    .bind(did)
    .fetch_optional(db)
    .await
    .unwrap_or(None);

    let target_collection = match tracked {
        Some((tc,)) => tc,
        None => return, // Not a tracked network lexicon.
    };

    match record.action.as_str() {
        "create" | "update" => {
            let rec = match &record.record {
                Some(r) => r,
                None => return,
            };

            let parsed = match ParsedLexicon::parse(
                rec.clone(),
                1,
                target_collection.clone(),
                ProcedureAction::Upsert,
                None,
                None,
            ) {
                Ok(p) => p,
                Err(e) => {
                    tracing::warn!(nsid, "failed to parse lexicon schema event: {e}");
                    return;
                }
            };

            let is_record = parsed.lexicon_type == crate::lexicon::LexiconType::Record;

            // Upsert into lexicons table with last_fetched_at.
            if let Err(e) = sqlx::query(
                r#"
                INSERT INTO lexicons (id, lexicon_json, backfill, target_collection, source, authority_did, last_fetched_at)
                VALUES ($1, $2, false, $3, 'network', $4, NOW())
                ON CONFLICT (id) DO UPDATE SET
                    lexicon_json = EXCLUDED.lexicon_json,
                    target_collection = EXCLUDED.target_collection,
                    last_fetched_at = NOW(),
                    revision = lexicons.revision + 1,
                    updated_at = NOW()
                "#,
            )
            .bind(nsid)
            .bind(rec)
            .bind(&target_collection)
            .bind(did)
            .execute(db)
            .await
            {
                tracing::warn!(nsid, "failed to upsert lexicon from event: {e}");
                return;
            }

            lexicons.upsert(parsed).await;
            tracing::info!(nsid, "updated network lexicon from tap event");

            if is_record {
                let collections = lexicons.get_record_collections().await;
                let _ = collections_tx.send(collections);
            }
        }
        "delete" => {
            // Remove from lexicons table and registry.
            let _ = sqlx::query("DELETE FROM lexicons WHERE id = $1")
                .bind(nsid)
                .execute(db)
                .await;

            let was_present = lexicons.remove(nsid).await;
            if was_present {
                tracing::info!(nsid, "removed network lexicon from tap delete event");
                let collections = lexicons.get_record_collections().await;
                let _ = collections_tx.send(collections);
            }
        }
        _ => {}
    }
}
