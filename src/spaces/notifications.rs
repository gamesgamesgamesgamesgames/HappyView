use serde::Deserialize;
use uuid::Uuid;

use crate::db::DatabaseBackend;
use crate::error::AppError;
use crate::spaces::db;
use crate::spaces::types::*;

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct WriteNotification {
    pub space_uri: String,
    pub author_did: String,
    pub collection: String,
    pub rkey: String,
    pub action: WriteAction,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum WriteAction {
    Create,
    Update,
    Delete,
}

/// Process a write notification by queuing a sync pull for the affected member.
///
/// This marks the member's sync state as pending so the next sync pass picks it up.
pub async fn handle_write_notification(
    pool: &sqlx::AnyPool,
    backend: DatabaseBackend,
    space_id: &str,
    notification: &WriteNotification,
) -> Result<(), AppError> {
    let existing = db::get_sync_state(pool, backend, space_id, &notification.author_did).await?;

    let state = SpaceSyncState {
        id: existing
            .map(|s| s.id)
            .unwrap_or_else(|| Uuid::new_v4().to_string()),
        space_id: space_id.to_string(),
        member_did: notification.author_did.clone(),
        cursor: None,
        last_synced_at: None,
        status: SyncStatus::Pending,
        error: None,
    };

    db::upsert_sync_state(pool, backend, &state).await?;

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn write_action_deserializes() {
        let action: WriteAction = serde_json::from_str("\"create\"").unwrap();
        assert!(matches!(action, WriteAction::Create));

        let action: WriteAction = serde_json::from_str("\"update\"").unwrap();
        assert!(matches!(action, WriteAction::Update));

        let action: WriteAction = serde_json::from_str("\"delete\"").unwrap();
        assert!(matches!(action, WriteAction::Delete));
    }

    #[test]
    fn write_notification_deserializes() {
        let json = r#"{
            "spaceUri": "ats://did:plc:owner/com.example.forum/main",
            "authorDid": "did:plc:alice",
            "collection": "com.example.forum.post",
            "rkey": "3k2abc",
            "action": "create"
        }"#;

        let notif: WriteNotification = serde_json::from_str(json).unwrap();
        assert_eq!(notif.author_did, "did:plc:alice");
        assert_eq!(notif.collection, "com.example.forum.post");
        assert!(matches!(notif.action, WriteAction::Create));
    }
}
