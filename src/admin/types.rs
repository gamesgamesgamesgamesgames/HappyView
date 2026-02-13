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
    pub(super) created_at: chrono::DateTime<chrono::Utc>,
    pub(super) updated_at: chrono::DateTime<chrono::Utc>,
}

#[derive(Deserialize)]
pub(super) struct UploadLexiconBody {
    pub(super) lexicon_json: Value,
    #[serde(default = "default_backfill")]
    pub(super) backfill: bool,
    pub(super) target_collection: Option<String>,
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
    pub(super) started_at: Option<chrono::DateTime<chrono::Utc>>,
    pub(super) completed_at: Option<chrono::DateTime<chrono::Utc>>,
    pub(super) created_at: chrono::DateTime<chrono::Utc>,
}

// ---------------------------------------------------------------------------
// Admin management types
// ---------------------------------------------------------------------------

#[derive(Deserialize)]
pub(super) struct CreateAdminBody {
    pub(super) did: String,
}

#[derive(Serialize)]
pub(super) struct AdminSummary {
    pub(super) id: String,
    pub(super) did: String,
    pub(super) created_at: chrono::DateTime<chrono::Utc>,
    pub(super) last_used_at: Option<chrono::DateTime<chrono::Utc>>,
}
