use std::collections::HashMap;
use std::sync::Arc;

use futures_util::StreamExt;
use serde::Deserialize;
use tokio::net::TcpStream;
use tokio::sync::watch;
use tokio::task::JoinHandle;
use tokio_tungstenite::tungstenite::Message;
use tokio_tungstenite::tungstenite::client::IntoClientRequest;

use crate::AppState;
use crate::event_log::{EventLog, Severity, log_event};
use crate::profile;

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

/// AT Protocol event stream frame header (DAG-CBOR).
#[derive(Deserialize)]
struct FrameHeader {
    op: i64,
    #[serde(default)]
    t: Option<String>,
}

#[derive(Deserialize)]
struct SubscribeLabelsMessage {
    seq: i64,
    labels: Vec<Label>,
}

#[derive(Deserialize)]
struct Label {
    src: String,
    uri: String,
    val: String,
    #[serde(default)]
    neg: bool,
    cts: String,
    exp: Option<String>,
}

// Used for the queryLabels HTTP response.
#[derive(Deserialize)]
struct QueryLabelsResponse {
    labels: Vec<Label>,
}

// ---------------------------------------------------------------------------
// Spawn — manages per-labeler subscription tasks
// ---------------------------------------------------------------------------

pub fn spawn(state: AppState, mut subscriptions_rx: watch::Receiver<()>) {
    tokio::spawn(async move {
        let mut tasks: HashMap<String, JoinHandle<()>> = HashMap::new();

        loop {
            // Read all active subscriptions from the database.
            let active: Vec<(String,)> =
                sqlx::query_as("SELECT did FROM labeler_subscriptions WHERE status = 'active'")
                    .fetch_all(&state.db)
                    .await
                    .unwrap_or_default();

            let active_dids: Vec<String> = active.into_iter().map(|(did,)| did).collect();

            // Stop tasks for removed/paused subscriptions.
            let to_remove: Vec<String> = tasks
                .keys()
                .filter(|did| !active_dids.contains(did))
                .cloned()
                .collect();

            for did in to_remove {
                if let Some(handle) = tasks.remove(&did) {
                    tracing::info!(did = %did, "stopping labeler subscription");
                    handle.abort();
                }
            }

            // Start tasks for new subscriptions.
            for did in &active_dids {
                if !tasks.contains_key(did) {
                    tracing::info!(did = %did, "starting labeler subscription");
                    let state = state.clone();
                    let did_clone = did.clone();
                    let handle = tokio::spawn(run_subscription(state, did_clone));
                    tasks.insert(did.clone(), handle);
                }
            }

            // Wait for a signal that subscriptions have changed.
            if subscriptions_rx.changed().await.is_err() {
                tracing::info!("labeler subscriptions channel closed, stopping");
                break;
            }
        }

        // Clean up all tasks on exit.
        for (_, handle) in tasks {
            handle.abort();
        }
    });
}

// ---------------------------------------------------------------------------
// Per-labeler reconnect loop
// ---------------------------------------------------------------------------

async fn run_subscription(state: AppState, did: String) {
    let mut backoff_secs: u64 = 2;
    const MAX_BACKOFF_SECS: u64 = 300; // 5 minutes

    loop {
        match run_subscription_once(&state, &did).await {
            Ok(()) => {
                tracing::info!(did = %did, "labeler subscription ended cleanly, reconnecting");
                backoff_secs = 2; // reset on clean disconnect
            }
            Err(e) => {
                tracing::warn!(did = %did, backoff = backoff_secs, "labeler subscription error: {e}");
            }
        }
        tokio::time::sleep(std::time::Duration::from_secs(backoff_secs)).await;
        tracing::info!(did = %did, "reconnecting to labeler");
        backoff_secs = (backoff_secs * 2).min(MAX_BACKOFF_SECS);
    }
}

// ---------------------------------------------------------------------------
// Single connection lifecycle
// ---------------------------------------------------------------------------

async fn run_subscription_once(
    state: &AppState,
    did: &str,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    // Resolve the labeler's service endpoint from its DID document.
    // Prefers #atproto_labeler, falls back to #atproto_pds.
    let pds_endpoint = profile::resolve_labeler_endpoint(&state.http, &state.config.plc_url, did)
        .await
        .map_err(|e| format!("failed to resolve labeler endpoint for {did}: {e:?}"))?;

    // Convert HTTP URL to WebSocket URL.
    let ws_url = http_to_ws(&pds_endpoint);

    // Read cursor from database.
    let cursor: Option<(Option<i64>,)> =
        sqlx::query_as("SELECT cursor FROM labeler_subscriptions WHERE did = $1")
            .bind(did)
            .fetch_optional(&state.db)
            .await?;

    let cursor_val = cursor.and_then(|(c,)| c).unwrap_or(0);

    let url = format!(
        "{}/xrpc/com.atproto.label.subscribeLabels?cursor={}",
        ws_url.trim_end_matches('/'),
        cursor_val
    );

    tracing::info!(did = %did, url = %url, "connecting to labeler");

    let request = url.into_client_request()?;

    // Manually establish TCP + TLS with HTTP/1.1 ALPN, then do the
    // WebSocket handshake over the established stream. This avoids
    // tokio-tungstenite's default TLS which may negotiate h2 via ALPN.
    let host = request
        .uri()
        .host()
        .ok_or("missing host in WebSocket URL")?
        .to_string();
    let port = request.uri().port_u16().unwrap_or(443);

    let tcp = TcpStream::connect((&*host, port)).await?;

    let _ = rustls::crypto::ring::default_provider().install_default();
    let root_store =
        rustls::RootCertStore::from_iter(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
    let mut tls_config = rustls::ClientConfig::builder()
        .with_root_certificates(root_store)
        .with_no_client_auth();
    tls_config.alpn_protocols = vec![b"http/1.1".to_vec()];

    let connector = tokio_rustls::TlsConnector::from(Arc::new(tls_config));
    let domain = rustls::pki_types::ServerName::try_from(host)?;
    let tls_stream = connector.connect(domain, tcp).await?;

    let (ws, _) = tokio_tungstenite::client_async(request, tls_stream).await?;

    tracing::info!(did = %did, "connected to labeler");

    log_event(
        &state.db,
        EventLog {
            event_type: "labeler.connected".to_string(),
            severity: Severity::Info,
            actor_did: None,
            subject: Some(did.to_string()),
            detail: serde_json::json!({ "did": did }),
        },
    )
    .await;

    let (_write, mut read) = ws.split();
    let mut events_since_cursor_save: u64 = 0;
    let mut last_seq: i64 = cursor_val;

    loop {
        let msg = match read.next().await {
            Some(Ok(m)) => m,
            Some(Err(e)) => {
                tracing::warn!(did = %did, "labeler websocket read error: {e}");
                // Persist cursor before disconnecting.
                persist_cursor(&state.db, did, last_seq).await;
                return Err(e.into());
            }
            None => {
                tracing::info!(did = %did, "labeler websocket stream ended");
                break;
            }
        };

        let bytes = match msg {
            Message::Binary(b) => b.to_vec(),
            Message::Close(_) => {
                tracing::info!(did = %did, "labeler websocket received close frame");
                break;
            }
            _ => continue,
        };

        // AT Protocol event streams use two concatenated DAG-CBOR objects:
        // 1. Frame header: { op: int, t: string? }
        // 2. Frame body: the actual message payload
        let message: SubscribeLabelsMessage = match parse_event_frame(&bytes) {
            Ok(Some(m)) => m,
            Ok(None) => continue, // non-message frame (error, info, etc.)
            Err(e) => {
                tracing::warn!(did = %did, "skipping unparseable labeler message: {e}");
                continue;
            }
        };

        last_seq = message.seq;

        for label in &message.labels {
            apply_label(&state.db, label).await;
        }

        events_since_cursor_save += 1;
        if events_since_cursor_save >= 100 {
            persist_cursor(&state.db, did, last_seq).await;
            events_since_cursor_save = 0;
        }
    }

    // Persist final cursor on disconnect.
    persist_cursor(&state.db, did, last_seq).await;

    log_event(
        &state.db,
        EventLog {
            event_type: "labeler.disconnected".to_string(),
            severity: Severity::Warn,
            actor_did: None,
            subject: Some(did.to_string()),
            detail: serde_json::json!({ "did": did, "last_seq": last_seq }),
        },
    )
    .await;

    Ok(())
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Parse an AT Protocol event stream frame (two concatenated DAG-CBOR objects).
/// Returns `Ok(Some(msg))` for label messages, `Ok(None)` for other frame types.
fn parse_event_frame(
    bytes: &[u8],
) -> Result<Option<SubscribeLabelsMessage>, Box<dyn std::error::Error + Send + Sync>> {
    let mut cursor = std::io::Cursor::new(bytes);

    // Decode frame header.
    let header: FrameHeader = ciborium::from_reader(&mut cursor)?;

    // op=1 is a regular message, op=-1 is an error frame.
    if header.op != 1 {
        return Ok(None);
    }

    // Only process #labels messages.
    match header.t.as_deref() {
        Some("#labels") => {}
        _ => return Ok(None),
    }

    // Decode the body (remaining bytes after header).
    let message: SubscribeLabelsMessage = ciborium::from_reader(&mut cursor)?;
    Ok(Some(message))
}

fn http_to_ws(url: &str) -> String {
    let base = url.trim_end_matches('/');
    if let Some(rest) = base.strip_prefix("https://") {
        format!("wss://{rest}")
    } else if let Some(rest) = base.strip_prefix("http://") {
        format!("ws://{rest}")
    } else {
        format!("ws://{base}")
    }
}

async fn apply_label(db: &sqlx::PgPool, label: &Label) {
    if label.neg {
        // Negation label — remove it.
        if let Err(e) = sqlx::query("DELETE FROM labels WHERE src = $1 AND uri = $2 AND val = $3")
            .bind(&label.src)
            .bind(&label.uri)
            .bind(&label.val)
            .execute(db)
            .await
        {
            tracing::warn!(
                src = %label.src, uri = %label.uri, val = %label.val,
                "failed to delete negated label: {e}"
            );
        }
    } else {
        // Normal label — upsert.
        let cts = chrono::DateTime::parse_from_rfc3339(&label.cts)
            .map(|dt| dt.with_timezone(&chrono::Utc))
            .ok();

        let exp = label
            .exp
            .as_deref()
            .and_then(|e| chrono::DateTime::parse_from_rfc3339(e).ok())
            .map(|dt| dt.with_timezone(&chrono::Utc));

        if let Err(e) = sqlx::query(
            r#"
            INSERT INTO labels (src, uri, val, cts, exp)
            VALUES ($1, $2, $3, $4, $5)
            ON CONFLICT (src, uri, val) DO UPDATE
                SET cts = EXCLUDED.cts,
                    exp = EXCLUDED.exp
            "#,
        )
        .bind(&label.src)
        .bind(&label.uri)
        .bind(&label.val)
        .bind(cts)
        .bind(exp)
        .execute(db)
        .await
        {
            tracing::warn!(
                src = %label.src, uri = %label.uri, val = %label.val,
                "failed to upsert label: {e}"
            );
        }
    }
}

async fn persist_cursor(db: &sqlx::PgPool, did: &str, seq: i64) {
    if let Err(e) = sqlx::query(
        "UPDATE labeler_subscriptions SET cursor = $1, updated_at = NOW() WHERE did = $2",
    )
    .bind(seq)
    .bind(did)
    .execute(db)
    .await
    {
        tracing::warn!(did = %did, seq, "failed to persist labeler cursor: {e}");
    }
}

// ---------------------------------------------------------------------------
// Backfill labels for a specific URI
// ---------------------------------------------------------------------------

/// Spawn a background task to backfill labels for a given URI from all active
/// labeler subscriptions. Fire-and-forget.
pub fn backfill_labels_for_uri(state: Arc<AppState>, uri: String) {
    tokio::spawn(async move {
        if let Err(e) = backfill_labels_for_uri_inner(&state, &uri).await {
            tracing::warn!(uri = %uri, "failed to backfill labels: {e}");
        }
    });
}

async fn backfill_labels_for_uri_inner(
    state: &AppState,
    uri: &str,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let subscriptions: Vec<(String,)> =
        sqlx::query_as("SELECT did FROM labeler_subscriptions WHERE status = 'active'")
            .fetch_all(&state.db)
            .await?;

    for (labeler_did,) in subscriptions {
        if let Err(e) = backfill_from_labeler(state, &labeler_did, uri).await {
            tracing::warn!(
                labeler = %labeler_did, uri = %uri,
                "failed to backfill labels from labeler: {e}"
            );
        }
    }

    Ok(())
}

async fn backfill_from_labeler(
    state: &AppState,
    labeler_did: &str,
    uri: &str,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let pds_endpoint =
        profile::resolve_pds_endpoint(&state.http, &state.config.plc_url, labeler_did)
            .await
            .map_err(|e| format!("failed to resolve PDS for {labeler_did}: {e:?}"))?;

    let encoded_uri = urlencoding::encode(uri);
    let url = format!(
        "{}/xrpc/com.atproto.label.queryLabels?uriPatterns={}",
        pds_endpoint.trim_end_matches('/'),
        encoded_uri
    );

    let resp = state.http.get(&url).send().await?;

    if !resp.status().is_success() {
        let status = resp.status();
        let body = resp.text().await.unwrap_or_default();
        return Err(format!("queryLabels returned {status}: {body}").into());
    }

    let response: QueryLabelsResponse = resp.json().await?;

    for label in &response.labels {
        apply_label(&state.db, label).await;
    }

    Ok(())
}

// ---------------------------------------------------------------------------
// Label garbage collection
// ---------------------------------------------------------------------------

/// Hourly task to clean up expired and orphaned labels.
pub async fn spawn_label_gc(db: sqlx::PgPool) {
    tracing::info!("starting label garbage collection task");

    let interval = tokio::time::Duration::from_secs(3600); // 1 hour
    loop {
        tokio::time::sleep(interval).await;

        // Delete expired labels.
        let expired = sqlx::query("DELETE FROM labels WHERE exp IS NOT NULL AND exp < NOW()")
            .execute(&db)
            .await;

        let expired_count = match expired {
            Ok(r) => r.rows_affected(),
            Err(e) => {
                tracing::warn!("failed to clean up expired labels: {e}");
                0
            }
        };

        // Delete orphaned labels (no matching record).
        let orphaned = sqlx::query(
            "DELETE FROM labels WHERE NOT EXISTS (SELECT 1 FROM records WHERE records.uri = labels.uri)",
        )
        .execute(&db)
        .await;

        let orphaned_count = match orphaned {
            Ok(r) => r.rows_affected(),
            Err(e) => {
                tracing::warn!("failed to clean up orphaned labels: {e}");
                0
            }
        };

        let total = expired_count + orphaned_count;
        if total > 0 {
            tracing::info!(
                expired = expired_count,
                orphaned = orphaned_count,
                "cleaned up {total} labels"
            );
        }
    }
}
