use std::collections::HashSet;

use serde::{Deserialize, Serialize};

/// All 23 permissions in the system.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum Permission {
    #[serde(rename = "lexicons:create")]
    LexiconsCreate,
    #[serde(rename = "lexicons:read")]
    LexiconsRead,
    #[serde(rename = "lexicons:delete")]
    LexiconsDelete,

    #[serde(rename = "records:read")]
    RecordsRead,
    #[serde(rename = "records:delete")]
    RecordsDelete,
    #[serde(rename = "records:delete-collection")]
    RecordsDeleteCollection,

    #[serde(rename = "script-variables:create")]
    ScriptVariablesCreate,
    #[serde(rename = "script-variables:read")]
    ScriptVariablesRead,
    #[serde(rename = "script-variables:delete")]
    ScriptVariablesDelete,

    #[serde(rename = "users:create")]
    UsersCreate,
    #[serde(rename = "users:read")]
    UsersRead,
    #[serde(rename = "users:update")]
    UsersUpdate,
    #[serde(rename = "users:delete")]
    UsersDelete,

    #[serde(rename = "api-keys:create")]
    ApiKeysCreate,
    #[serde(rename = "api-keys:read")]
    ApiKeysRead,
    #[serde(rename = "api-keys:delete")]
    ApiKeysDelete,

    #[serde(rename = "backfill:create")]
    BackfillCreate,
    #[serde(rename = "backfill:read")]
    BackfillRead,

    #[serde(rename = "stats:read")]
    StatsRead,

    #[serde(rename = "events:read")]
    EventsRead,

    #[serde(rename = "labelers:create")]
    LabelersCreate,
    #[serde(rename = "labelers:read")]
    LabelersRead,
    #[serde(rename = "labelers:delete")]
    LabelersDelete,

    #[serde(rename = "rate-limits:read")]
    RateLimitsRead,
    #[serde(rename = "rate-limits:create")]
    RateLimitsCreate,
    #[serde(rename = "rate-limits:delete")]
    RateLimitsDelete,
}

impl Permission {
    /// String representation matching the DB values.
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::LexiconsCreate => "lexicons:create",
            Self::LexiconsRead => "lexicons:read",
            Self::LexiconsDelete => "lexicons:delete",
            Self::RecordsRead => "records:read",
            Self::RecordsDelete => "records:delete",
            Self::RecordsDeleteCollection => "records:delete-collection",
            Self::ScriptVariablesCreate => "script-variables:create",
            Self::ScriptVariablesRead => "script-variables:read",
            Self::ScriptVariablesDelete => "script-variables:delete",
            Self::UsersCreate => "users:create",
            Self::UsersRead => "users:read",
            Self::UsersUpdate => "users:update",
            Self::UsersDelete => "users:delete",
            Self::ApiKeysCreate => "api-keys:create",
            Self::ApiKeysRead => "api-keys:read",
            Self::ApiKeysDelete => "api-keys:delete",
            Self::BackfillCreate => "backfill:create",
            Self::BackfillRead => "backfill:read",
            Self::StatsRead => "stats:read",
            Self::EventsRead => "events:read",
            Self::LabelersCreate => "labelers:create",
            Self::LabelersRead => "labelers:read",
            Self::LabelersDelete => "labelers:delete",
            Self::RateLimitsRead => "rate-limits:read",
            Self::RateLimitsCreate => "rate-limits:create",
            Self::RateLimitsDelete => "rate-limits:delete",
        }
    }

    /// All 26 permissions.
    pub fn all() -> HashSet<Permission> {
        HashSet::from([
            Self::LexiconsCreate,
            Self::LexiconsRead,
            Self::LexiconsDelete,
            Self::RecordsRead,
            Self::RecordsDelete,
            Self::RecordsDeleteCollection,
            Self::ScriptVariablesCreate,
            Self::ScriptVariablesRead,
            Self::ScriptVariablesDelete,
            Self::UsersCreate,
            Self::UsersRead,
            Self::UsersUpdate,
            Self::UsersDelete,
            Self::ApiKeysCreate,
            Self::ApiKeysRead,
            Self::ApiKeysDelete,
            Self::BackfillCreate,
            Self::BackfillRead,
            Self::StatsRead,
            Self::EventsRead,
            Self::LabelersCreate,
            Self::LabelersRead,
            Self::LabelersDelete,
            Self::RateLimitsRead,
            Self::RateLimitsCreate,
            Self::RateLimitsDelete,
        ])
    }
}

/// Predefined permission templates.
#[derive(Debug, Clone, Copy, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Template {
    Viewer,
    Operator,
    Manager,
    FullAccess,
}

impl Template {
    pub fn permissions(&self) -> HashSet<Permission> {
        match self {
            Self::Viewer => HashSet::from([
                Permission::LexiconsRead,
                Permission::RecordsRead,
                Permission::ScriptVariablesRead,
                Permission::UsersRead,
                Permission::ApiKeysRead,
                Permission::BackfillRead,
                Permission::StatsRead,
                Permission::EventsRead,
            ]),
            Self::Operator => {
                let mut perms = Self::Viewer.permissions();
                perms.insert(Permission::BackfillCreate);
                perms.insert(Permission::ApiKeysCreate);
                perms.insert(Permission::ApiKeysDelete);
                perms
            }
            Self::Manager => {
                let mut perms = Self::Operator.permissions();
                perms.insert(Permission::LexiconsCreate);
                perms.insert(Permission::LexiconsDelete);
                perms.insert(Permission::ScriptVariablesCreate);
                perms.insert(Permission::ScriptVariablesDelete);
                perms.insert(Permission::RecordsDelete);
                perms.insert(Permission::LabelersCreate);
                perms.insert(Permission::LabelersRead);
                perms.insert(Permission::LabelersDelete);
                perms.insert(Permission::RateLimitsRead);
                perms.insert(Permission::RateLimitsCreate);
                perms.insert(Permission::RateLimitsDelete);
                perms
            }
            Self::FullAccess => Permission::all(),
        }
    }
}
