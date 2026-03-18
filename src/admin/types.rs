use serde::{Deserialize, Serialize};
use serde_json::Value;

// ---------------------------------------------------------------------------
// Lexicon types
// ---------------------------------------------------------------------------

#[derive(Serialize)]
pub(super) struct LexiconSummary {
    pub(super) id: String,
    pub(super) revision: i32,
    pub(super) lexicon_type: String,
    pub(super) backfill: bool,
    pub(super) action: Option<String>,
    pub(super) target_collection: Option<String>,
    pub(super) has_script: bool,
    pub(super) has_index_hook: bool,
    pub(super) source: String,
    pub(super) authority_did: Option<String>,
    pub(super) last_fetched_at: Option<String>,
    pub(super) created_at: String,
    pub(super) updated_at: String,
    /// For record-type lexicons: the `properties` object from `defs.main.record`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(super) record_schema: Option<Value>,
    pub(super) token_cost: Option<i32>,
}

#[derive(Deserialize)]
pub(super) struct UploadLexiconBody {
    pub(super) lexicon_json: Value,
    #[serde(default = "default_backfill")]
    pub(super) backfill: bool,
    pub(super) target_collection: Option<String>,
    pub(super) action: Option<String>,
    pub(super) script: Option<String>,
    pub(super) index_hook: Option<String>,
    pub(super) token_cost: Option<i32>,
}

fn default_backfill() -> bool {
    true
}

// ---------------------------------------------------------------------------
// Stats types
// ---------------------------------------------------------------------------

#[derive(Serialize)]
pub(super) struct StatsResponse {
    pub(super) total_records: i64,
    pub(super) collections: Vec<CollectionStat>,
}

#[derive(Serialize)]
pub(super) struct CollectionStat {
    pub(super) collection: String,
    pub(super) count: i64,
}

// ---------------------------------------------------------------------------
// Backfill types
// ---------------------------------------------------------------------------

#[derive(Deserialize)]
pub(super) struct CreateBackfillBody {
    pub(super) collection: Option<String>,
    pub(super) did: Option<String>,
}

#[derive(Serialize)]
pub(super) struct BackfillJob {
    pub(super) id: String,
    pub(super) collection: Option<String>,
    pub(super) did: Option<String>,
    pub(super) status: String,
    pub(super) total_repos: Option<i32>,
    pub(super) processed_repos: Option<i32>,
    pub(super) total_records: Option<i32>,
    pub(super) error: Option<String>,
    pub(super) started_at: Option<String>,
    pub(super) completed_at: Option<String>,
    pub(super) created_at: String,
}

// ---------------------------------------------------------------------------
// Network lexicon types
// ---------------------------------------------------------------------------

#[derive(Deserialize)]
pub(super) struct AddNetworkLexiconBody {
    pub(super) nsid: String,
    pub(super) target_collection: Option<String>,
}

#[derive(Serialize)]
pub(super) struct NetworkLexiconSummary {
    pub(super) nsid: String,
    pub(super) authority_did: String,
    pub(super) target_collection: Option<String>,
    pub(super) last_fetched_at: Option<String>,
    pub(super) created_at: String,
}

// ---------------------------------------------------------------------------
// User management types
// ---------------------------------------------------------------------------

#[derive(Deserialize)]
pub(super) struct CreateUserBody {
    pub(super) did: String,
    pub(super) template: Option<super::permissions::Template>,
    pub(super) permissions: Option<Vec<String>>,
}

#[derive(Serialize)]
pub(super) struct UserSummary {
    pub(super) id: String,
    pub(super) did: String,
    pub(super) is_super: bool,
    pub(super) permissions: Vec<String>,
    pub(super) created_at: String,
    pub(super) last_used_at: Option<String>,
}

// ---------------------------------------------------------------------------
// API key types
// ---------------------------------------------------------------------------

#[derive(Deserialize)]
pub(super) struct CreateApiKeyBody {
    pub(super) name: String,
    pub(super) permissions: Vec<String>,
}

#[derive(Serialize)]
pub(super) struct ApiKeySummary {
    pub(super) id: String,
    pub(super) name: String,
    pub(super) key_prefix: String,
    pub(super) permissions: Vec<String>,
    pub(super) created_at: String,
    pub(super) last_used_at: Option<String>,
    pub(super) revoked_at: Option<String>,
}

#[derive(Serialize)]
pub(super) struct CreateApiKeyResponse {
    pub(super) id: String,
    pub(super) name: String,
    pub(super) key: String,
    pub(super) key_prefix: String,
    pub(super) permissions: Vec<String>,
}

// ---------------------------------------------------------------------------
// Script variable types
// ---------------------------------------------------------------------------

#[derive(Serialize)]
pub(super) struct ScriptVariableSummary {
    pub(super) key: String,
    pub(super) preview: String,
    pub(super) created_at: String,
    pub(super) updated_at: String,
}

#[derive(Deserialize)]
pub(super) struct UpsertScriptVariableBody {
    pub(super) key: String,
    pub(super) value: String,
}

// ---------------------------------------------------------------------------
// Labeler subscription types
// ---------------------------------------------------------------------------

#[derive(Deserialize)]
pub(super) struct AddLabelerBody {
    pub(super) did: String,
}

#[derive(Serialize)]
pub(super) struct LabelerSummary {
    pub(super) did: String,
    pub(super) status: String,
    pub(super) cursor: Option<i64>,
    pub(super) created_at: String,
    pub(super) updated_at: String,
}

#[derive(Deserialize)]
pub(super) struct UpdateLabelerBody {
    pub(super) status: String,
}

// ---------------------------------------------------------------------------
// User permission / transfer types
// ---------------------------------------------------------------------------

#[derive(Deserialize)]
pub(super) struct UpdatePermissionsBody {
    #[serde(default)]
    pub(super) grant: Vec<String>,
    #[serde(default)]
    pub(super) revoke: Vec<String>,
}

#[derive(Deserialize)]
pub(super) struct TransferSuperBody {
    pub(super) target_user_id: String,
}

// ---------------------------------------------------------------------------
// Rate limit types
// ---------------------------------------------------------------------------

#[derive(Deserialize)]
pub(super) struct UpsertRateLimitBody {
    pub(super) capacity: u32,
    pub(super) refill_rate: f64,
    pub(super) default_query_cost: u32,
    pub(super) default_procedure_cost: u32,
    pub(super) default_proxy_cost: u32,
}

#[derive(Deserialize)]
pub(super) struct SetEnabledBody {
    pub(super) enabled: bool,
}

#[derive(Deserialize)]
pub(super) struct AddAllowlistBody {
    pub(super) cidr: String,
    pub(super) note: Option<String>,
}

#[derive(Serialize)]
pub(super) struct RateLimitsResponse {
    pub(super) enabled: bool,
    pub(super) capacity: i32,
    pub(super) refill_rate: f32,
    pub(super) default_query_cost: i32,
    pub(super) default_procedure_cost: i32,
    pub(super) default_proxy_cost: i32,
    pub(super) allowlist: Vec<AllowlistEntry>,
}

#[derive(Serialize)]
pub(super) struct AllowlistEntry {
    pub(super) id: i32,
    pub(super) cidr: String,
    pub(super) note: Option<String>,
    pub(super) created_at: String,
}
