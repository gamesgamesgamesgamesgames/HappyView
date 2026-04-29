use serde::{Deserialize, Serialize};
use std::fmt;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum SpaceAccess {
    Read,
    Write,
}

impl SpaceAccess {
    pub fn as_str(&self) -> &'static str {
        match self {
            SpaceAccess::Read => "read",
            SpaceAccess::Write => "write",
        }
    }

    pub fn parse(s: &str) -> Option<Self> {
        match s {
            "read" => Some(SpaceAccess::Read),
            "write" => Some(SpaceAccess::Write),
            _ => None,
        }
    }

    pub fn can_write(&self) -> bool {
        matches!(self, SpaceAccess::Write)
    }

    pub fn can_read(&self) -> bool {
        true
    }
}

impl fmt::Display for SpaceAccess {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AccessMode {
    DefaultAllow,
    DefaultDeny,
}

impl AccessMode {
    pub fn as_str(&self) -> &'static str {
        match self {
            AccessMode::DefaultAllow => "default_allow",
            AccessMode::DefaultDeny => "default_deny",
        }
    }

    pub fn parse(s: &str) -> Option<Self> {
        match s {
            "default_allow" => Some(AccessMode::DefaultAllow),
            "default_deny" => Some(AccessMode::DefaultDeny),
            _ => None,
        }
    }
}

impl fmt::Display for AccessMode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Space {
    pub id: String,
    pub owner_did: String,
    pub type_nsid: String,
    pub skey: String,
    pub display_name: Option<String>,
    pub description: Option<String>,
    pub access_mode: AccessMode,
    pub app_allowlist: Option<Vec<String>>,
    pub app_denylist: Option<Vec<String>>,
    pub managing_app_did: Option<String>,
    pub config: SpaceConfig,
    pub created_at: String,
    pub updated_at: String,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct SpaceConfig {
    #[serde(default)]
    pub membership_public: bool,
    #[serde(default)]
    pub records_public: bool,
    #[serde(flatten)]
    pub extra: serde_json::Map<String, serde_json::Value>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SpaceMember {
    pub id: String,
    pub space_id: String,
    pub member_did: String,
    pub access: SpaceAccess,
    pub is_delegation: bool,
    pub granted_by: Option<String>,
    pub created_at: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResolvedMember {
    pub did: String,
    pub access: SpaceAccess,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SpaceRecord {
    pub uri: String,
    pub space_id: String,
    pub author_did: String,
    pub collection: String,
    pub rkey: String,
    pub record: serde_json::Value,
    pub cid: String,
    pub indexed_at: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SpaceInvite {
    pub id: String,
    pub space_id: String,
    pub token_hash: String,
    pub created_by: String,
    pub access: SpaceAccess,
    pub max_uses: Option<i64>,
    pub uses: i64,
    pub expires_at: Option<String>,
    pub revoked: bool,
    pub created_at: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum SyncStatus {
    Pending,
    Syncing,
    Synced,
    Error,
}

impl SyncStatus {
    pub fn as_str(&self) -> &'static str {
        match self {
            SyncStatus::Pending => "pending",
            SyncStatus::Syncing => "syncing",
            SyncStatus::Synced => "synced",
            SyncStatus::Error => "error",
        }
    }

    pub fn parse(s: &str) -> Option<Self> {
        match s {
            "pending" => Some(SyncStatus::Pending),
            "syncing" => Some(SyncStatus::Syncing),
            "synced" => Some(SyncStatus::Synced),
            "error" => Some(SyncStatus::Error),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SpaceSyncState {
    pub id: String,
    pub space_id: String,
    pub member_did: String,
    pub cursor: Option<String>,
    pub last_synced_at: Option<String>,
    pub status: SyncStatus,
    pub error: Option<String>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn space_access_roundtrip() {
        assert_eq!(SpaceAccess::parse("read"), Some(SpaceAccess::Read));
        assert_eq!(SpaceAccess::parse("write"), Some(SpaceAccess::Write));
        assert_eq!(SpaceAccess::parse("admin"), None);

        assert_eq!(SpaceAccess::Read.as_str(), "read");
        assert_eq!(SpaceAccess::Write.as_str(), "write");
    }

    #[test]
    fn space_access_permissions() {
        assert!(SpaceAccess::Read.can_read());
        assert!(!SpaceAccess::Read.can_write());
        assert!(SpaceAccess::Write.can_read());
        assert!(SpaceAccess::Write.can_write());
    }

    #[test]
    fn access_mode_roundtrip() {
        assert_eq!(
            AccessMode::parse("default_allow"),
            Some(AccessMode::DefaultAllow)
        );
        assert_eq!(
            AccessMode::parse("default_deny"),
            Some(AccessMode::DefaultDeny)
        );
        assert_eq!(AccessMode::parse("open"), None);
    }

    #[test]
    fn space_config_defaults() {
        let config: SpaceConfig = serde_json::from_str("{}").unwrap();
        assert!(!config.membership_public);
        assert!(!config.records_public);
    }

    #[test]
    fn space_config_with_extra_fields() {
        let config: SpaceConfig =
            serde_json::from_str(r#"{"membership_public": true, "custom_field": 42}"#).unwrap();
        assert!(config.membership_public);
        assert!(!config.records_public);
        assert_eq!(config.extra.get("custom_field").unwrap(), &42);
    }

    #[test]
    fn space_access_serialization() {
        let json = serde_json::to_string(&SpaceAccess::Read).unwrap();
        assert_eq!(json, "\"read\"");

        let json = serde_json::to_string(&SpaceAccess::Write).unwrap();
        assert_eq!(json, "\"write\"");

        let parsed: SpaceAccess = serde_json::from_str("\"read\"").unwrap();
        assert_eq!(parsed, SpaceAccess::Read);

        let parsed: SpaceAccess = serde_json::from_str("\"write\"").unwrap();
        assert_eq!(parsed, SpaceAccess::Write);
    }
}
