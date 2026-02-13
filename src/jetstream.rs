use futures_util::StreamExt;
use serde::Deserialize;
use serde_json::Value;
use sqlx::PgPool;
use std::sync::atomic::{AtomicI64, Ordering};
use std::sync::Arc;
use tokio::sync::watch;
use tokio_tungstenite::tungstenite::Message;

// ---------------------------------------------------------------------------
// Jetstream event types
// ---------------------------------------------------------------------------

#[derive(Deserialize)]
struct JetstreamEvent {
    did: String,
    time_us: i64,
    kind: String,
    commit: Option<JetstreamCommit>,
}

#[derive(Deserialize)]
struct JetstreamCommit {
    operation: String,
    collection: String,
    rkey: String,
    record: Option<Value>,
    cid: Option<String>,
}

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

/// Spawn a background task that subscribes to the Jetstream firehose and
/// indexes records for collections specified by the watch channel.
///
/// When the collection list is empty, the task idles without connecting.
/// When collections change, it disconnects and reconnects with the new filter.
pub fn spawn(db: PgPool, jetstream_url: String, mut collections_rx: watch::Receiver<Vec<String>>) {
    tokio::spawn(async move {
        let cursor: Arc<AtomicI64> = Arc::new(AtomicI64::new(0));

        loop {
            // Wait until we have at least one collection to subscribe to.
            let collections = collections_rx.borrow_and_update().clone();
            if collections.is_empty() {
                tracing::info!("no collections configured, jetstream idle");
                // Block until the collection list changes.
                if collections_rx.changed().await.is_err() {
                    // Sender dropped — shut down.
                    tracing::info!("jetstream watch channel closed, shutting down");
                    return;
                }
                continue;
            }

            // Connect and process events. If the collection list changes
            // mid-stream, `run` returns so we can reconnect with new filters.
            match run(&db, &jetstream_url, &cursor, &collections, &mut collections_rx).await {
                Ok(()) => {
                    tracing::info!("jetstream reconnecting due to collection change");
                }
                Err(e) => {
                    tracing::warn!("jetstream disconnected: {e}");
                    tokio::time::sleep(std::time::Duration::from_secs(2)).await;
                    tracing::info!("reconnecting to jetstream...");
                }
            }
        }
    });
}

// ---------------------------------------------------------------------------
// Connection loop
// ---------------------------------------------------------------------------

async fn run(
    db: &PgPool,
    jetstream_url: &str,
    cursor: &Arc<AtomicI64>,
    collections: &[String],
    collections_rx: &mut watch::Receiver<Vec<String>>,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let wanted: String = collections
        .iter()
        .map(|c| format!("wantedCollections={c}"))
        .collect::<Vec<_>>()
        .join("&");

    let mut url = format!("{jetstream_url}?{wanted}");

    let last = cursor.load(Ordering::Relaxed);
    if last > 0 {
        // Rewind 5 seconds for gapless playback.
        let rewound = last - 5_000_000;
        url.push_str(&format!("&cursor={rewound}"));
        tracing::info!(cursor = rewound, "resuming jetstream with cursor");
    }

    tracing::info!(collections = ?collections, "connecting to jetstream");

    let (ws, _) = tokio_tungstenite::connect_async(&url).await?;
    tracing::info!("connected to jetstream");

    let (_, mut read) = ws.split();

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

                let event: JetstreamEvent = match serde_json::from_str(&text) {
                    Ok(e) => e,
                    Err(e) => {
                        tracing::debug!("skipping unparseable event: {e}");
                        continue;
                    }
                };

                // Update cursor.
                cursor.store(event.time_us, Ordering::Relaxed);

                if event.kind != "commit" {
                    continue;
                }

                let commit = match event.commit {
                    Some(c) => c,
                    None => continue,
                };

                let uri = format!(
                    "at://{}/{}/{}",
                    event.did, commit.collection, commit.rkey,
                );

                match commit.operation.as_str() {
                    "create" | "update" => {
                        let record = match commit.record {
                            Some(r) => r,
                            None => continue,
                        };
                        let cid = commit.cid.unwrap_or_default();

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
                        .bind(&event.did)
                        .bind(&commit.collection)
                        .bind(&commit.rkey)
                        .bind(&record)
                        .bind(&cid)
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
            // If the collection list changes, break out to reconnect.
            _ = collections_rx.changed() => {
                tracing::info!("collection filter changed, will reconnect");
                return Ok(());
            }
        }
    }

    Ok(())
}
