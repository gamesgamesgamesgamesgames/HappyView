use futures_util::{SinkExt, StreamExt};
use serde::Deserialize;
use serde_json::Value;
use sqlx::PgPool;
use tokio::sync::watch;
use tokio_tungstenite::tungstenite::Message;
use tokio_tungstenite::tungstenite::client::IntoClientRequest;

use crate::lexicon::{LexiconRegistry, ParsedLexicon, ProcedureAction};

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
pub fn spawn(
    db: PgPool,
    tap_url: String,
    tap_admin_password: Option<String>,
    mut collections_rx: watch::Receiver<Vec<String>>,
    lexicons: LexiconRegistry,
    collections_tx: watch::Sender<Vec<String>>,
) {
    let http = reqwest::Client::new();

    tokio::spawn(async move {
        loop {
            // Build WebSocket URL from HTTP URL.
            let ws_url = build_ws_url(&tap_url);

            match run(
                &db,
                &http,
                &tap_url,
                tap_admin_password.as_deref(),
                &ws_url,
                &mut collections_rx,
                &lexicons,
                &collections_tx,
            )
            .await
            {
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

#[allow(clippy::too_many_arguments)]
async fn run(
    db: &PgPool,
    http: &reqwest::Client,
    tap_url: &str,
    tap_admin_password: Option<&str>,
    ws_url: &str,
    collections_rx: &mut watch::Receiver<Vec<String>>,
    lexicons: &LexiconRegistry,
    collections_tx: &watch::Sender<Vec<String>>,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
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
                            handle_record_event(db, lexicons, collections_tx, &record).await;
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

    Ok(())
}

// ---------------------------------------------------------------------------
// Record event handler
// ---------------------------------------------------------------------------

async fn handle_record_event(
    db: &PgPool,
    lexicons: &LexiconRegistry,
    collections_tx: &watch::Sender<Vec<String>>,
    record: &TapRecordEvent,
) {
    let uri = format!("at://{}/{}/{}", record.did, record.collection, record.rkey,);

    // Handle lexicon schema events for tracked network lexicons.
    if record.collection == LEXICON_SCHEMA_COLLECTION {
        handle_lexicon_schema_event(db, lexicons, collections_tx, &record.did, record).await;
        return;
    }

    match record.action.as_str() {
        "create" | "update" => {
            let rec = match &record.record {
                Some(r) => r,
                None => return,
            };
            let cid = record.cid.as_deref().unwrap_or_default();

            if let Err(e) = sqlx::query(
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
            .bind(rec)
            .bind(cid)
            .execute(db)
            .await
            {
                tracing::warn!(uri = %uri, "failed to upsert record: {e}");
            }
        }
        "delete" => {
            if let Err(e) = sqlx::query("DELETE FROM records WHERE uri = $1")
                .bind(&uri)
                .execute(db)
                .await
            {
                tracing::warn!(uri = %uri, "failed to delete record: {e}");
            }
        }
        _ => {}
    }
}

// ---------------------------------------------------------------------------
// Lexicon schema event handler
// ---------------------------------------------------------------------------

/// Handle a `com.atproto.lexicon.schema` record event for tracked network lexicons.
async fn handle_lexicon_schema_event(
    db: &PgPool,
    lexicons: &LexiconRegistry,
    collections_tx: &watch::Sender<Vec<String>>,
    did: &str,
    record: &TapRecordEvent,
) {
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
